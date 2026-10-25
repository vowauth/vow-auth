import type { IdentityClaims, IdentityStore } from "@vow-auth/core";

type Row = {
	readonly tenant: string;
	readonly provider: string;
	readonly externalId: string;
	readonly subjectId: string;
	readonly email: string | undefined;
	readonly emailVerified: boolean;
};

type Subject = {
	readonly tenant: string;
	evictedAtMilliseconds: number | undefined;
};

const identityKey = (
	tenant: string,
	provider: string,
	externalId: string,
): string => JSON.stringify([tenant, provider, externalId]);

/**
 * In-process identity store for tests and single-instance development. It
 * keeps the subjects and one row per identity, in order of arrival, exactly as
 * the Postgres store does, so the two answer alike: the owner of a verified
 * email is the oldest identity that verified it, deleting that identity hands
 * the email to the next one, and a subject emptied by an eviction stays,
 * marked evicted. Lookups by email scan the rows, which is fine at the size of
 * a test.
 */
export function createMemoryIdentityStore(): IdentityStore {
	const subjects = new Map<string, Subject>();
	const rows = new Map<string, Row>();

	const liveSubject = (tenant: string, subjectId: string): boolean => {
		const subject = subjects.get(subjectId);

		return (
			subject !== undefined &&
			subject.tenant === tenant &&
			subject.evictedAtMilliseconds === undefined
		);
	};

	const insert = (
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): void => {
		rows.set(identityKey(tenant, identity.provider, identity.externalId), {
			tenant,
			provider: identity.provider,
			externalId: identity.externalId,
			subjectId,
			email: identity.email?.address,
			emailVerified: identity.emailVerified,
		});
	};

	const ownerOf = (tenant: string, identity: IdentityClaims) =>
		rows.get(identityKey(tenant, identity.provider, identity.externalId))
			?.subjectId;

	const withEmail = (
		tenant: string,
		address: string,
		verified: boolean,
	): Row[] =>
		Array.from(rows.values()).filter(
			(row) =>
				row.tenant === tenant &&
				row.email === address &&
				row.emailVerified === verified,
		);

	const verifiedOwner = (tenant: string, address: string) =>
		withEmail(tenant, address, true)[0]?.subjectId;

	const hasIdentity = (tenant: string, subjectId: string): boolean =>
		Array.from(rows.values()).some(
			(row) => row.tenant === tenant && row.subjectId === subjectId,
		);

	return {
		async findSubject(tenant, provider, externalId) {
			return rows.get(identityKey(tenant, provider, externalId))?.subjectId;
		},
		async findSubjectByVerifiedEmail(tenant, email) {
			return verifiedOwner(tenant, email.address);
		},
		async createSubject(tenant, identity) {
			const existing = ownerOf(tenant, identity);

			if (existing !== undefined) {
				return { subjectId: existing, isNew: false };
			}

			const subjectId = crypto.randomUUID();

			subjects.set(subjectId, { tenant, evictedAtMilliseconds: undefined });
			insert(tenant, subjectId, identity);

			return { subjectId, isNew: true };
		},
		async linkIdentity(tenant, subjectId, identity) {
			const existing = ownerOf(tenant, identity);

			if (existing !== undefined) {
				return existing;
			}

			if (!liveSubject(tenant, subjectId)) {
				return undefined;
			}

			insert(tenant, subjectId, identity);

			return subjectId;
		},
		async getSubject(tenant, subjectId) {
			const subject = subjects.get(subjectId);

			if (subject === undefined || subject.tenant !== tenant) {
				return undefined;
			}

			return { evictedAtMilliseconds: subject.evictedAtMilliseconds };
		},
		async findSubjectsByUnverifiedEmail(tenant, email) {
			return Array.from(
				new Set(
					withEmail(tenant, email.address, false).map((row) => row.subjectId),
				),
			);
		},
		async removeUnverifiedEmailClaims(tenant, email, keepSubjectId) {
			const owner = verifiedOwner(tenant, email.address);
			const claims = withEmail(tenant, email.address, false).filter(
				(row) => row.subjectId !== keepSubjectId && row.subjectId !== owner,
			);

			for (const row of claims) {
				rows.delete(identityKey(row.tenant, row.provider, row.externalId));
			}

			const touched = Array.from(new Set(claims.map((row) => row.subjectId)));
			const now = Date.now();

			for (const subjectId of touched) {
				const subject = subjects.get(subjectId);

				if (subject !== undefined && !hasIdentity(tenant, subjectId)) {
					subject.evictedAtMilliseconds ??= now;
				}
			}

			return touched;
		},
		async deleteSubject(tenant, subjectId) {
			const subject = subjects.get(subjectId);

			if (subject === undefined || subject.tenant !== tenant) {
				return false;
			}

			subjects.delete(subjectId);

			for (const [key, row] of rows) {
				if (row.tenant === tenant && row.subjectId === subjectId) {
					rows.delete(key);
				}
			}

			return true;
		},
	};
}
