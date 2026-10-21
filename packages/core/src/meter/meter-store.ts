/** One request to count against a limit. */
export type MeterConsumeInput = {
	readonly key: string;
	readonly cost: number;
	readonly limit: number;
	readonly windowMilliseconds: number;
};

/** How much of a limit is used, and when the window ends. */
export type MeterReading = {
	readonly used: number;
	readonly remaining: number;
	readonly resetsAtMilliseconds: number;
};

/** What the store answers: the reading, and whether the cost was counted. */
export type MeterStoreResult = MeterReading & { readonly allowed: boolean };

/**
 * Storage port for counters shared by every instance. `consume` must be one
 * atomic step by the store's own clock: it starts a window of
 * `windowMilliseconds` when the key has none running, counts the cost when
 * `used + cost` stays within `limit` and answers `allowed: true`, and counts
 * nothing and answers `allowed: false` otherwise. A store that cannot count,
 * for example because it is full, must answer `allowed: false`, never `true`.
 */
export type MeterStore = {
	consume(input: MeterConsumeInput): Promise<MeterStoreResult>;
};
