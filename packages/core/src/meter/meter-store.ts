/** One request to count against a limit. */
export type MeterConsumeInput = {
	readonly key: string;
	readonly cost: number;
	readonly limit: number;
	readonly windowMilliseconds: number;
};

/**
 * How much of a limit is used. `used` is the estimated rate rounded up.
 * `resetsAtMilliseconds` is the earliest moment a refused request would pass,
 * and for an allowed one the moment the key reads zero again.
 */
export type MeterReading = {
	readonly used: number;
	readonly remaining: number;
	readonly resetsAtMilliseconds: number;
};

/** What the store answers: the reading, and whether the cost was counted. */
export type MeterStoreResult = MeterReading & { readonly allowed: boolean };

/**
 * Storage port for counters shared by every instance. `consume` must be one
 * atomic step by the store's own clock, and it must decide as `slidingWindow`
 * does: two counters per key, the sliding window approximation of Cloudflare's
 * rate limiting. It counts the cost and answers `allowed: true` when the
 * request fits, and counts nothing and answers `allowed: false` otherwise. A
 * store that cannot count, for example because it is full, must answer
 * `allowed: false`, never `true`.
 */
export type MeterStore = {
	consume(input: MeterConsumeInput): Promise<MeterStoreResult>;
};
