import type { IdentityClaims, IdentityStore } from "@vow-auth/core";

type Row = {
	readonly tenant: string;
	readonly provider: string;
	readonly externalId: string;
	readonly subjectId: string;
	readonly email: string | undefined;
	readonly emailVerified: boolean;
};

const identityKey = (
	tenant: string,
	provider: string,
	externalId: string,
): string => JSON.stringify([tenant, provider, externalId]);

/**
 * In-process identity store for tests and single-instance development. It
 * keeps one row per identity, in order of arrival, and a subject is the
 * `subjectId` of its rows, exactly as the Postgres store does, so the two
 * answer alike: the owner of a verified email is the oldest identity that
 * verified it, and deleting that identity hands the email to the next one.
 * Lookups by email scan the rows, which is fine at the size of a test.
 */
export function createMemoryIdentityStore(): IdentityStore {
	const rows = new Map<string, Row>();

	const attach = (
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): string => {
		const key = identityKey(tenant, identity.provider, identity.externalId);
		const existing = rows.get(key);

		if (existing !== undefined) {
			return existing.subjectId;
		}

		rows.set(key, {
			tenant,
			provider: identity.provider,
			externalId: identity.externalId,
			subjectId,
			email: identity.email?.address,
			emailVerified: identity.emailVerified,
		});

		return subjectId;
	};

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

	return {
		async findSubject(tenant, provider, externalId) {
			return rows.get(identityKey(tenant, provider, externalId))?.subjectId;
		},
		async findSubjectByVerifiedEmail(tenant, email) {
			return verifiedOwner(tenant, email.address);
		},
		async createSubject(tenant, identity) {
			const subjectId = crypto.randomUUID();
			const owner = attach(tenant, subjectId, identity);

			return { subjectId: owner, isNew: owner === subjectId };
		},
		async linkIdentity(tenant, subjectId, identity) {
			return attach(tenant, subjectId, identity);
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

			return Array.from(new Set(claims.map((row) => row.subjectId)));
		},
		async deleteSubject(tenant, subjectId) {
			let deleted = false;

			for (const [key, row] of rows) {
				if (row.tenant === tenant && row.subjectId === subjectId) {
					rows.delete(key);
					deleted = true;
				}
			}

			return deleted;
		},
	};
}
