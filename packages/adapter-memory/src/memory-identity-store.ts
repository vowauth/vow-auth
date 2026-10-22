import type {
	CanonicalEmail,
	IdentityClaims,
	IdentityStore,
} from "@vow-auth/core";

type StoredSubject = {
	readonly tenant: string;
	readonly identities: Map<string, IdentityClaims>;
};

const identityKey = (
	tenant: string,
	provider: string,
	externalId: string,
): string => JSON.stringify([tenant, provider, externalId]);

const emailKey = (tenant: string, email: CanonicalEmail): string =>
	JSON.stringify([tenant, email.address]);

/** In-process identity store for tests and single-instance development. */
export function createMemoryIdentityStore(): IdentityStore {
	const subjects = new Map<string, StoredSubject>();
	const subjectsByIdentity = new Map<string, string>();
	const subjectsByVerifiedEmail = new Map<string, string>();
	const subjectsByUnverifiedEmail = new Map<string, Set<string>>();

	const forget = (
		tenant: string,
		subjectId: string,
		key: string,
		identity: IdentityClaims,
	): void => {
		subjectsByIdentity.delete(key);

		if (identity.email === undefined) {
			return;
		}

		const byEmail = emailKey(tenant, identity.email);

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
			forget(subject.tenant, subjectId, key, identity);
		}

		subjects.delete(subjectId);
	};

	const attach = (
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): string => {
		const key = identityKey(tenant, identity.provider, identity.externalId);
		const owner = subjectsByIdentity.get(key);

		if (owner !== undefined) {
			return owner;
		}

		subjectsByIdentity.set(key, subjectId);

		const subject = subjects.get(subjectId) ?? {
			tenant,
			identities: new Map<string, IdentityClaims>(),
		};

		subject.identities.set(key, identity);
		subjects.set(subjectId, subject);

		if (identity.emailVerified) {
			const verifiedKey = emailKey(tenant, identity.email);

			if (!subjectsByVerifiedEmail.has(verifiedKey)) {
				subjectsByVerifiedEmail.set(verifiedKey, subjectId);
			}
		} else if (identity.email !== undefined) {
			const unverifiedKey = emailKey(tenant, identity.email);
			const claimants =
				subjectsByUnverifiedEmail.get(unverifiedKey) ?? new Set<string>();

			claimants.add(subjectId);
			subjectsByUnverifiedEmail.set(unverifiedKey, claimants);
		}

		return subjectId;
	};

	return {
		async findSubject(tenant, provider, externalId) {
			return subjectsByIdentity.get(identityKey(tenant, provider, externalId));
		},
		async findSubjectByVerifiedEmail(tenant, email) {
			return subjectsByVerifiedEmail.get(emailKey(tenant, email));
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
				subjectsByUnverifiedEmail.get(emailKey(tenant, email)) ?? [],
			);
		},
		async removeUnverifiedEmailClaims(tenant, email, keepSubjectId) {
			const byEmail = emailKey(tenant, email);
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
		async deleteSubject(tenant, subjectId) {
			if (subjects.get(subjectId)?.tenant !== tenant) {
				return false;
			}

			removeSubject(subjectId);

			return true;
		},
	};
}
