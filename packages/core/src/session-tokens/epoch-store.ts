/** What one read of the epoch store returns: its own time and the stamps. */
export type EpochReading = {
	/** The store's current Unix time in milliseconds, by the store's clock. */
	readonly now: number;
	/** One stamp per requested key, in the order of the keys. */
	readonly stamps: readonly number[];
};

/**
 * Storage port for revocation stamps and the only clock of session tokens.
 * Every level of a token chain has a key holding the stamp of its last
 * revocation; a missing or expired key reads as 0. Token expiry, revocation
 * stamps and key lifetimes all use the store's clock, so the clocks of the
 * application servers never matter. An adapter must guarantee all of the
 * following; a backend that cannot is not a valid epoch store.
 *
 * - `read` takes the store's time and every key of a chain in one atomic
 *   round trip.
 * - `revoke` is atomic: by the store's clock it sets the key to
 *   `max(current + 1, now)` with the given time to live and returns the new
 *   stamp. A stamp never decreases while its key lives.
 * - The store's clock does not step backward. A backward step of length Δ, or
 *   a failover to a replica whose clock lags by Δ, lets a token revoked just
 *   after its issue live up to Δ longer; the adapter documents its bound.
 * - Strong consistency: a completed `revoke` is visible to `read` on every
 *   instance. Eventually consistent stores, such as Cloudflare Workers KV,
 *   delay revocation.
 * - Durability: losing stamps revives every token revoked within their time
 *   to live, so a store without persistence does not qualify.
 * - Failures throw.
 */
export type EpochStore = {
	/** Reads the store's time and the stamps of all keys in one round trip. */
	read(keys: readonly string[]): Promise<EpochReading>;
	/** Atomically raises the stamp to `max(current + 1, now)` by the store's clock and returns it. */
	revoke(key: string, timeToLiveMilliseconds: number): Promise<number>;
};
