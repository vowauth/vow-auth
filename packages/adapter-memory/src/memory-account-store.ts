import type {
	AccountStore,
	StoredAccount,
	StoredIdentity,
	StoredMembership,
	StoredTenant,
} from "@vow-auth/core";

type IdentityRow = StoredIdentity & { readonly seq: number };

const identityKey = (provider: string, externalId: string): string =>
	JSON.stringify([provider, externalId]);

const pairKey = (tenant: string, accountId: string): string =>
	JSON.stringify([tenant, accountId]);

/**
 * In-process account store for tests and single-instance development. It
 * keeps tenants, accounts, one row per identity in order of arrival and one
 * row per membership, exactly as the Postgres store does, so the two answer
 * alike: an identity is unique in the deployment, a membership is unique for
 * a tenant and an account, the owner of a verified email is the oldest
 * identity of a trusted provider that verified it, and an account emptied by
 * an eviction stays, marked evicted. Every method runs to its end before
 * another starts, which makes each one atomic. Lookups by email scan the
 * rows, which is fine at the size of a test.
 */
export function createMemoryAccountStore(): AccountStore {
	const tenants = new Map<string, StoredTenant>();
	const accounts = new Map<string, StoredAccount>();
	const identities = new Map<string, IdentityRow>();
	const memberships = new Map<string, StoredMembership>();
	const pairs = new Map<string, string>();
	let seq = 0;

	const liveAccount = (id: string): boolean => {
		const account = accounts.get(id);

		return account !== undefined && !account.evicted;
	};

	const membershipFits = (membership: StoredMembership): boolean =>
		membership.accountId !== undefined &&
		tenants.has(membership.tenant) &&
		!memberships.has(membership.subjectId) &&
		!pairs.has(pairKey(membership.tenant, membership.accountId));

	const putIdentity = (identity: StoredIdentity): void => {
		seq += 1;
		identities.set(identityKey(identity.provider, identity.externalId), {
			...identity,
			seq,
		});
	};

	const putMembership = (membership: StoredMembership): void => {
		memberships.set(membership.subjectId, membership);

		if (membership.accountId !== undefined) {
			pairs.set(
				pairKey(membership.tenant, membership.accountId),
				membership.subjectId,
			);
		}
	};

	const identityOf = (row: IdentityRow): StoredIdentity => ({
		provider: row.provider,
		externalId: row.externalId,
		accountId: row.accountId,
		email: row.email,
		emailVerified: row.emailVerified,
		seal: row.seal,
	});

	const claims = (
		email: string,
		keepAccountId: string,
		trustedProviders: readonly string[],
	): IdentityRow[] =>
		Array.from(identities.values())
			.filter(
				(row) =>
					row.email === email &&
					row.accountId !== keepAccountId &&
					!(row.emailVerified && trustedProviders.includes(row.provider)),
			)
			.sort((left, right) => left.seq - right.seq);

	const distinctAccounts = (rows: readonly IdentityRow[]): string[] =>
		Array.from(new Set(rows.map((row) => row.accountId)));

	return {
		async getTenant(id) {
			return tenants.get(id);
		},
		async createTenant(tenant) {
			if (tenants.has(tenant.id)) {
				return "conflict";
			}

			tenants.set(tenant.id, tenant);

			return "created";
		},
		async setTenant(tenant, expectedSeal) {
			if (tenants.get(tenant.id)?.seal !== expectedSeal) {
				return false;
			}

			tenants.set(tenant.id, tenant);

			return true;
		},
		async findIdentity(provider, externalId) {
			const row = identities.get(identityKey(provider, externalId));

			return row === undefined ? undefined : identityOf(row);
		},
		async findVerifiedOwner(email, providers) {
			const owner = Array.from(identities.values())
				.filter(
					(row) =>
						row.email === email &&
						row.emailVerified &&
						providers.includes(row.provider),
				)
				.sort((left, right) => left.seq - right.seq)[0];

			return owner === undefined ? undefined : identityOf(owner);
		},
		async getAccount(id) {
			return accounts.get(id);
		},
		async setAccount(account, expectedSeal) {
			const current = accounts.get(account.id);

			if (current === undefined || current.seal !== expectedSeal) {
				return false;
			}

			accounts.set(account.id, { ...account, evicted: current.evicted });

			return true;
		},
		async findMembership(tenant, accountId) {
			const subjectId = pairs.get(pairKey(tenant, accountId));

			return subjectId === undefined ? undefined : memberships.get(subjectId);
		},
		async getMembership(tenant, subjectId) {
			const membership = memberships.get(subjectId);

			return membership?.tenant === tenant ? membership : undefined;
		},
		async listMemberships(accountId) {
			return Array.from(memberships.values()).filter(
				(membership) => membership.accountId === accountId,
			);
		},
		async createAccount(account, identity, membership) {
			if (
				accounts.has(account.id) ||
				identities.has(identityKey(identity.provider, identity.externalId)) ||
				(membership !== undefined && !membershipFits(membership))
			) {
				return "conflict";
			}

			accounts.set(account.id, account);
			putIdentity(identity);

			if (membership !== undefined) {
				putMembership(membership);
			}

			return "created";
		},
		async linkIdentity(identity) {
			if (identities.has(identityKey(identity.provider, identity.externalId))) {
				return "conflict";
			}

			if (!liveAccount(identity.accountId)) {
				return "missing";
			}

			putIdentity(identity);

			return "linked";
		},
		async updateIdentity(identity, expectedSeal) {
			const key = identityKey(identity.provider, identity.externalId);
			const row = identities.get(key);

			if (row === undefined || row.seal !== expectedSeal) {
				return false;
			}

			identities.set(key, { ...identity, seq: row.seq });

			return true;
		},
		async createMembership(membership) {
			if (
				!membershipFits(membership) ||
				membership.accountId === undefined ||
				!liveAccount(membership.accountId)
			) {
				return "conflict";
			}

			putMembership(membership);

			return "created";
		},
		async setMembership(membership, expectedSeal) {
			const current = memberships.get(membership.subjectId);

			if (
				current === undefined ||
				current.tenant !== membership.tenant ||
				current.accountId !== membership.accountId ||
				current.seal !== expectedSeal
			) {
				return false;
			}

			memberships.set(membership.subjectId, membership);

			return true;
		},
		async findEmailClaimants(email, keepAccountId, trustedProviders) {
			return distinctAccounts(claims(email, keepAccountId, trustedProviders));
		},
		async evictEmailClaims(email, keepAccountId, trustedProviders) {
			const removed = claims(email, keepAccountId, trustedProviders);

			for (const row of removed) {
				identities.delete(identityKey(row.provider, row.externalId));
			}

			const touched = distinctAccounts(removed);

			for (const accountId of touched) {
				const account = accounts.get(accountId);
				const kept = Array.from(identities.values()).some(
					(row) => row.accountId === accountId,
				);

				if (account !== undefined && !kept) {
					accounts.set(accountId, { ...account, evicted: true });
				}
			}

			return touched;
		},
		async deleteAccount(id) {
			if (!accounts.has(id)) {
				return undefined;
			}

			for (const [key, row] of identities) {
				if (row.accountId === id) {
					identities.delete(key);
				}
			}

			const left: StoredMembership[] = [];

			for (const membership of memberships.values()) {
				if (membership.accountId === id) {
					const orphan: StoredMembership = {
						...membership,
						accountId: undefined,
						status: "removed",
					};

					pairs.delete(pairKey(membership.tenant, id));
					memberships.set(membership.subjectId, orphan);
					left.push(orphan);
				}
			}

			accounts.delete(id);

			return left;
		},
	};
}
