import type {
	CanonicalEmail,
	IdentityClaims,
	IdentityStore,
} from "@vow-auth/core";

type StoredSubject = {
	readonly tenantId: string;
	readonly identities: Map<string, IdentityClaims>;
};

const identityKey = (
	tenantId: string,
	provider: string,
	externalId: string,
): string => JSON.stringify([tenantId, provider, externalId]);

const emailKey = (tenantId: string, email: CanonicalEmail): string =>
	JSON.stringify([tenantId, email.address]);

/** In-process identity store for tests and single-instance development. */
export function createMemoryIdentityStore(): IdentityStore {
	const subjects = new Map<string, StoredSubject>();
	const subjectsByIdentity = new Map<string, string>();
	const subjectsByVerifiedEmail = new Map<string, string>();
	const subjectsByUnverifiedEmail = new Map<string, Set<string>>();

	const forget = (
		tenantId: string,
		subjectId: string,
		key: string,
		identity: IdentityClaims,
	): void => {
		subjectsByIdentity.delete(key);

		if (identity.email === undefined) {
			return;
		}

		const byEmail = emailKey(tenantId, identity.email);

		if (subjectsByVerifiedEmail.get(byEmail) === subjectId) {
			subjectsByVerifiedEmail.delete(byEmail);
		}

		subjectsByUnverifiedEmail.get(byEmail)?.delete(subjectId);
	};

	const removeSubject = (subjectId: string): void => {
		const subject = subjects.get(subjectId);

		if (subject === undefined) {
			return;
		}

		for (const [key, identity] of subject.identities) {
			forget(subject.tenantId, subjectId, key, identity);
		}

		subjects.delete(subjectId);
	};

	const attach = (
		tenantId: string,
		subjectId: string,
		identity: IdentityClaims,
	): string => {
		const key = identityKey(tenantId, identity.provider, identity.externalId);
		const owner = subjectsByIdentity.get(key);

		if (owner !== undefined) {
			return owner;
		}

		subjectsByIdentity.set(key, subjectId);

		const subject = subjects.get(subjectId) ?? {
			tenantId,
			identities: new Map<string, IdentityClaims>(),
		};

		subject.identities.set(key, identity);
		subjects.set(subjectId, subject);

		if (identity.emailVerified) {
			const verifiedKey = emailKey(tenantId, identity.email);

			if (!subjectsByVerifiedEmail.has(verifiedKey)) {
				subjectsByVerifiedEmail.set(verifiedKey, subjectId);
			}
		} else if (identity.email !== undefined) {
			const unverifiedKey = emailKey(tenantId, identity.email);
			const claimants =
				subjectsByUnverifiedEmail.get(unverifiedKey) ?? new Set<string>();

			claimants.add(subjectId);
			subjectsByUnverifiedEmail.set(unverifiedKey, claimants);
		}

		return subjectId;
	};

	return {
		async findSubject(tenantId, provider, externalId) {
			return subjectsByIdentity.get(
				identityKey(tenantId, provider, externalId),
			);
		},
		async findSubjectByVerifiedEmail(tenantId, email) {
			return subjectsByVerifiedEmail.get(emailKey(tenantId, email));
		},
		async createSubject(tenantId, identity) {
			const subjectId = crypto.randomUUID();
			const owner = attach(tenantId, subjectId, identity);

			return { subjectId: owner, created: owner === subjectId };
		},
		async linkIdentity(tenantId, subjectId, identity) {
			return attach(tenantId, subjectId, identity);
		},
		async findSubjectsByUnverifiedEmail(tenantId, email) {
			return Array.from(
				subjectsByUnverifiedEmail.get(emailKey(tenantId, email)) ?? [],
			);
		},
		async removeUnverifiedEmailClaims(tenantId, email, keepSubjectId) {
			const byEmail = emailKey(tenantId, email);
			const owner = subjectsByVerifiedEmail.get(byEmail);
			const touched: string[] = [];

			for (const subjectId of Array.from(
				subjectsByUnverifiedEmail.get(byEmail) ?? [],
			)) {
				const subject = subjects.get(subjectId);

				if (
					subject === undefined ||
					subjectId === keepSubjectId ||
					subjectId === owner
				) {
					continue;
				}

				touched.push(subjectId);

				for (const [key, identity] of subject.identities) {
					if (
						!identity.emailVerified &&
						identity.email?.address === email.address
					) {
						subject.identities.delete(key);
						subjectsByIdentity.delete(key);
					}
				}

				if (subject.identities.size === 0) {
					removeSubject(subjectId);
				}

				subjectsByUnverifiedEmail.get(byEmail)?.delete(subjectId);
			}

			return touched;
		},
		async deleteSubject(tenantId, subjectId) {
			if (subjects.get(subjectId)?.tenantId !== tenantId) {
				return false;
			}

			removeSubject(subjectId);

			return true;
		},
	};
}
