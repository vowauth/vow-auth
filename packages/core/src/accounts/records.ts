import type { StoredGrant } from "../grants/grant-store.js";
import type { RecordCheck, RecordSeal } from "../record-seal.js";
import type {
	StoredAccount,
	StoredIdentity,
	StoredMembership,
	StoredTenant,
	TenantSigningKey,
} from "./account-store.js";

/** A record before the engine sealed it. */
export type Unsealed<Record> = Omit<Record, "seal">;

const byKid = (keys: readonly TenantSigningKey[]): TenantSigningKey[] =>
	[...keys].sort((left, right) =>
		left.kid < right.kid ? -1 : left.kid > right.kid ? 1 : 0,
	);

const tenantFields = (tenant: Unsealed<StoredTenant>) => [
	"tenant",
	tenant.id,
	tenant.disabled,
	tenant.version,
	JSON.stringify(byKid(tenant.signingKeys).map((key) => [key.kid, key.state])),
];

const accountFields = (account: Unsealed<StoredAccount>) => [
	"account",
	account.id,
	account.managedByTenant ?? null,
];

const identityFields = (identity: Unsealed<StoredIdentity>) => [
	"identity",
	identity.provider,
	identity.externalId,
	identity.accountId,
	identity.email ?? null,
	identity.emailVerified,
];

const membershipFields = (membership: Unsealed<StoredMembership>) => [
	"membership",
	membership.subjectId,
	membership.tenant,
	membership.accountId ?? null,
	membership.status,
];

const grantFields = (grant: Unsealed<StoredGrant>) => [
	"grant",
	grant.id,
	grant.kind,
	grant.tokenHash ?? null,
	grant.accountId,
	grant.tenant ?? null,
	grant.subjectId ?? null,
	grant.device ?? null,
	grant.agent ?? null,
	grant.parentId ?? null,
	grant.sessionId ?? null,
	grant.proofs ?? null,
	grant.authenticatedAtMilliseconds,
	grant.expiresAtMilliseconds,
];

/**
 * Seals and checks each kind of record. The kind is the first field, so a
 * seal of one kind never passes for another. A tenant's seal covers its
 * version and the id and state of each of its signing keys, so a key row
 * brought back or changed past the engine breaks the seal of its tenant. The
 * eviction mark of an account is not sealed: it only takes access away, and
 * an evicted account has no identity left to sign in with. Neither are the
 * revocation mark and the idle
 * end of a grant: the first only takes access away, the second moves while a
 * session is used and never past the end, which is sealed.
 */
export const createRecords = (seal: RecordSeal) => {
	return {
		async tenant(tenant: Unsealed<StoredTenant>): Promise<StoredTenant> {
			return Object.freeze({
				id: tenant.id,
				disabled: tenant.disabled,
				version: tenant.version,
				signingKeys: Object.freeze(
					byKid(tenant.signingKeys).map((key) =>
						Object.freeze({ kid: key.kid, state: key.state }),
					),
				),
				seal: await seal.seal(tenantFields(tenant)),
			});
		},
		async account(account: Unsealed<StoredAccount>): Promise<StoredAccount> {
			return Object.freeze({
				id: account.id,
				managedByTenant: account.managedByTenant,
				evicted: account.evicted,
				seal: await seal.seal(accountFields(account)),
			});
		},
		async identity(
			identity: Unsealed<StoredIdentity>,
		): Promise<StoredIdentity> {
			return Object.freeze({
				provider: identity.provider,
				externalId: identity.externalId,
				accountId: identity.accountId,
				email: identity.email,
				emailVerified: identity.emailVerified,
				seal: await seal.seal(identityFields(identity)),
			});
		},
		async membership(
			membership: Unsealed<StoredMembership>,
		): Promise<StoredMembership> {
			return Object.freeze({
				subjectId: membership.subjectId,
				tenant: membership.tenant,
				accountId: membership.accountId,
				status: membership.status,
				seal: await seal.seal(membershipFields(membership)),
			});
		},
		async grant(grant: Unsealed<StoredGrant>): Promise<StoredGrant> {
			return Object.freeze({
				id: grant.id,
				kind: grant.kind,
				tokenHash: grant.tokenHash,
				accountId: grant.accountId,
				tenant: grant.tenant,
				subjectId: grant.subjectId,
				device: grant.device,
				agent: grant.agent,
				parentId: grant.parentId,
				sessionId: grant.sessionId,
				proofs: grant.proofs,
				authenticatedAtMilliseconds: grant.authenticatedAtMilliseconds,
				expiresAtMilliseconds: grant.expiresAtMilliseconds,
				idleExpiresAtMilliseconds: grant.idleExpiresAtMilliseconds,
				revoked: grant.revoked,
				seal: await seal.seal(grantFields(grant)),
			});
		},
		checkTenant: (tenant: StoredTenant): Promise<RecordCheck> =>
			seal.check(tenantFields(tenant), tenant.seal),
		checkAccount: (account: StoredAccount): Promise<RecordCheck> =>
			seal.check(accountFields(account), account.seal),
		checkIdentity: (identity: StoredIdentity): Promise<RecordCheck> =>
			seal.check(identityFields(identity), identity.seal),
		checkMembership: (membership: StoredMembership): Promise<RecordCheck> =>
			seal.check(membershipFields(membership), membership.seal),
		checkGrant: (grant: StoredGrant): Promise<RecordCheck> =>
			seal.check(grantFields(grant), grant.seal),
	};
};

export type Records = ReturnType<typeof createRecords>;
