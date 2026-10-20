import type { IdentityClaims, IdentityStore } from "@vow-auth/core";

const identityKey = (
	tenantId: string,
	provider: string,
	externalId: string,
): string => JSON.stringify([tenantId, provider, externalId]);

const emailKey = (tenantId: string, email: string): string =>
	JSON.stringify([tenantId, email]);

/** In-process identity store for tests and single-instance development. */
export function createMemoryIdentityStore(): IdentityStore {
	const subjectsByIdentity = new Map<string, string>();
	const subjectsByVerifiedEmail = new Map<string, string>();

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

		if (identity.emailVerified) {
			const verifiedKey = emailKey(tenantId, identity.email);

			if (!subjectsByVerifiedEmail.has(verifiedKey)) {
				subjectsByVerifiedEmail.set(verifiedKey, subjectId);
			}
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
	};
}
