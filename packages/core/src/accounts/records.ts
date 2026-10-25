import type { RecordCheck, RecordSeal } from "../record-seal.js";
import type {
	StoredAccount,
	StoredIdentity,
	StoredMembership,
	StoredTenant,
} from "./account-store.js";

/** A record before the engine sealed it. */
export type Unsealed<Record> = Omit<Record, "seal">;

const tenantFields = (tenant: Unsealed<StoredTenant>) => [
	"tenant",
	tenant.id,
	tenant.disabled,
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

/**
 * Seals and checks each kind of record. The kind is the first field, so a
 * seal of one kind never passes for another. The eviction mark of an account
 * is not sealed: it only takes access away, and an evicted account has no
 * identity left to sign in with.
 */
export const createRecords = (seal: RecordSeal) => {
	return {
		async tenant(tenant: Unsealed<StoredTenant>): Promise<StoredTenant> {
			return Object.freeze({
				id: tenant.id,
				disabled: tenant.disabled,
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
		checkTenant: (tenant: StoredTenant): Promise<RecordCheck> =>
			seal.check(tenantFields(tenant), tenant.seal),
		checkAccount: (account: StoredAccount): Promise<RecordCheck> =>
			seal.check(accountFields(account), account.seal),
		checkIdentity: (identity: StoredIdentity): Promise<RecordCheck> =>
			seal.check(identityFields(identity), identity.seal),
		checkMembership: (membership: StoredMembership): Promise<RecordCheck> =>
			seal.check(membershipFields(membership), membership.seal),
	};
};

export type Records = ReturnType<typeof createRecords>;
