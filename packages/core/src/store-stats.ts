/**
 * What an operator needs to watch a store: how full it is and whether it has
 * had to turn work away or drop live records. The application calls the
 * store's `stats()` when its own metrics collector asks, for example on every
 * scrape; the core never calls it on the request path. A number that a store
 * cannot know is `undefined`, never a guess.
 */
export type StoreStats = {
	readonly entries: number | undefined;
	readonly usedBytes: number | undefined;
	readonly maximumBytes: number | undefined;
	/** Writes refused for lack of room since the store started. */
	readonly capacityRefusals: number | undefined;
	/** Live records dropped to make room since the store started. A safe store keeps this at zero; any rise is worth an alert. */
	readonly evictions: number | undefined;
};
