/** Where a signing key of a tenant stands: published ahead of use, signing, or kept only to check what it signed. */
export type SigningKeyState = "next" | "current" | "previous";

/** The id and state of a signing key, as the seal of its tenant covers them. */
export type TenantSigningKey = {
	readonly kid: string;
	readonly state: SigningKeyState;
};

/** A tenant as the store keeps it. */
export type StoredTenant = {
	readonly id: string;
	readonly disabled: boolean;
	/** Grows by one with every change the engine makes, so whatever was built from the tenant knows when to be built again. */
	readonly version: number;
	/** Its signing keys by kid, read from the keys themselves; they change only through `setSigningKeys`. */
	readonly signingKeys: readonly TenantSigningKey[];
	readonly seal: string;
};

/** A signing key of a tenant as the store keeps it. */
export type StoredSigningKey = TenantSigningKey & {
	/** The private JWK, sealed for its tenant and kid; the public key is part of it. */
	readonly privateKey: string;
	/** When the store first kept the key, by its clock. Not sealed: it only holds back the next rotation. */
	readonly publishedAtMilliseconds: number;
};

/** A signing key to write; the store sets the time it is published. */
export type NewSigningKey = Omit<StoredSigningKey, "publishedAtMilliseconds">;

/** A tenant with its signing keys by kid, read at once, and the store's time. */
export type SigningKeyReading = {
	readonly tenant: StoredTenant;
	readonly keys: readonly StoredSigningKey[];
	readonly now: number;
};

/** A person in the data zone of this deployment, one across all tenants. */
export type StoredAccount = {
	readonly id: string;
	/** The tenant that manages the account; `undefined` for a personal one. */
	readonly managedByTenant: string | undefined;
	/** Set by an eviction that left the account without identities; not part of the seal, it only takes access away. */
	readonly evicted: boolean;
	readonly seal: string;
};

/** A way to prove that a person is the owner of an account. */
export type StoredIdentity = {
	readonly provider: string;
	readonly externalId: string;
	readonly accountId: string;
	readonly email: string | undefined;
	readonly emailVerified: boolean;
	readonly seal: string;
};

/** Where a membership stands: in, held back, or out with its id kept for a return. */
export type MembershipStatus = "active" | "suspended" | "removed";

/**
 * An account inside a tenant: the subject the data of the application points
 * at. Its id stays the same for the pair of account and tenant.
 */
export type StoredMembership = {
	readonly subjectId: string;
	readonly tenant: string;
	/** `undefined` once the account was deleted: the row stays for the foreign keys of the application. */
	readonly accountId: string | undefined;
	readonly status: MembershipStatus;
	readonly seal: string;
};

/**
 * Storage port of tenants, accounts, their identities and memberships. An
 * identity is unique in the deployment, a membership is unique for a tenant
 * and an account. Every write is atomic. `create*` and `linkIdentity` are
 * first-wins: on a conflict nothing changes and the call says so. `set*` and
 * `updateIdentity` are compare-and-set on the seal the caller read: a row that
 * changed in between is left alone and the call answers `false`. Seals are
 * opaque to the store; it keeps and returns them as they are. A tenant lists
 * its signing keys by kid in the order of their code units, as JavaScript
 * sorts strings; `createTenant` and `setTenant` write the tenant alone, and
 * only `setSigningKeys` changes its keys. An adapter must guarantee all of
 * this; a backend that cannot is not a valid account store.
 */
export type AccountStore = {
	getTenant(id: string): Promise<StoredTenant | undefined>;
	/** A new tenant has no signing keys, whatever its record lists. */
	createTenant(tenant: StoredTenant): Promise<"created" | "conflict">;
	setTenant(tenant: StoredTenant, expectedSeal: string): Promise<boolean>;
	/** The tenant and its signing keys by kid, read at once; `undefined` when there is no such tenant. */
	getSigningKeys(tenant: string): Promise<SigningKeyReading | undefined>;
	/**
	 * At once, and only when the tenant still has `expectedSeal`: writes the
	 * tenant and makes its keys exactly `keys`. A key left out is deleted, a new
	 * one is published at the store's time, and one that stays keeps its time.
	 * `false` when the tenant changed or does not exist; nothing is written then.
	 */
	setSigningKeys(
		tenant: StoredTenant,
		expectedSeal: string,
		keys: readonly NewSigningKey[],
	): Promise<boolean>;

	findIdentity(
		provider: string,
		externalId: string,
	): Promise<StoredIdentity | undefined>;
	/** The oldest identity of one of `providers` that verified the email. */
	findVerifiedOwner(
		email: string,
		providers: readonly string[],
	): Promise<StoredIdentity | undefined>;
	getAccount(id: string): Promise<StoredAccount | undefined>;
	/** Replaces the sealed fields; the eviction mark stays as it is. */
	setAccount(account: StoredAccount, expectedSeal: string): Promise<boolean>;
	findMembership(
		tenant: string,
		accountId: string,
	): Promise<StoredMembership | undefined>;
	getMembership(
		tenant: string,
		subjectId: string,
	): Promise<StoredMembership | undefined>;
	listMemberships(accountId: string): Promise<readonly StoredMembership[]>;

	/**
	 * The account, its first identity and, when given, its first membership, at
	 * once. `conflict` when the identity, the account or the membership exists,
	 * and then nothing is written.
	 */
	createAccount(
		account: StoredAccount,
		identity: StoredIdentity,
		membership: StoredMembership | undefined,
	): Promise<"created" | "conflict">;
	/** Adds an identity to an account that exists and is not evicted; `missing` otherwise. */
	linkIdentity(
		identity: StoredIdentity,
	): Promise<"linked" | "conflict" | "missing">;
	updateIdentity(
		identity: StoredIdentity,
		expectedSeal: string,
	): Promise<boolean>;
	/** A membership of an account that exists and is not evicted; `conflict` when the pair or the id exists, or the account does not. */
	createMembership(
		membership: StoredMembership,
	): Promise<"created" | "conflict">;
	setMembership(
		membership: StoredMembership,
		expectedSeal: string,
	): Promise<boolean>;

	/**
	 * The accounts other than `keepAccountId` that claim the email without a
	 * verification by one of `trustedProviders`.
	 */
	findEmailClaimants(
		email: string,
		keepAccountId: string,
		trustedProviders: readonly string[],
	): Promise<readonly string[]>;
	/**
	 * At once: removes every claim of the email that is not verified by one of
	 * `trustedProviders` from every account except `keepAccountId`, marks the
	 * accounts left without identities evicted, and returns every account it
	 * touched.
	 */
	evictEmailClaims(
		email: string,
		keepAccountId: string,
		trustedProviders: readonly string[],
	): Promise<readonly string[]>;
	/**
	 * Deletes the account and its identities at once. Its memberships stay,
	 * with no account and the status `removed`; they are returned as they are
	 * after the call. `undefined` when there is no such account.
	 */
	deleteAccount(id: string): Promise<readonly StoredMembership[] | undefined>;
};
