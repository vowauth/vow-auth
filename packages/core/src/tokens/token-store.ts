/** Stored form of an issued token. The secret itself is never stored, only its hash. */
export type TokenRecord = {
	readonly purpose: string;
	readonly payload: Readonly<Record<string, string>>;
	readonly expiresAtMilliseconds: number;
};

/**
 * Storage port for tokens. An adapter must guarantee all of the following; a
 * backend that cannot is not a valid token store.
 *
 * - Atomic `take`: of any number of concurrent `take` calls for one hash, at
 *   most one receives the record. A separate read and delete is not atomic.
 * - Strong consistency: a completed `put` is visible to `take` on every
 *   instance, and a completed `take` is a deletion on every instance.
 *   Eventually consistent stores, such as Cloudflare Workers KV, do not qualify.
 * - Failures throw. `undefined` from `take` means only that no record exists.
 * - Expiry is checked by the caller. A native TTL in the backend is garbage
 *   collection only: it may delete late, or early by the clock skew between
 *   the backend and the application.
 * - The adapter documents whether a failover can bring a taken record back.
 *   With asynchronous replication it can, within the replication lag.
 */
export type TokenStore = {
	/** Stores a record under the hash of its token. */
	put(hash: string, record: TokenRecord): Promise<void>;
	/** Atomically removes and returns the record, or `undefined` when there is none. */
	take(hash: string): Promise<TokenRecord | undefined>;
};
