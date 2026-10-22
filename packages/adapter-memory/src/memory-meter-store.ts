import {
	type MeterStore,
	type SlidingWindowState,
	type StoreStats,
	slidingWindow,
} from "@vow-auth/core";
import { estimateBytes } from "./estimate-bytes.js";
import { createExpiryOrder } from "./expiry-order.js";

/** Options of the in-process meter store. */
export type MemoryMeterStoreOptions = {
	/**
	 * Memory budget in bytes; a counter costs 256 bytes plus 2 bytes per
	 * character of its key. When a new key does not fit after expired counters
	 * are dropped, the store refuses it: counters are never forgotten early,
	 * because forgetting one would reset a limit.
	 */
	readonly maximumBytes: number;
};

/** The meter store, with the numbers an operator watches. */
export type MemoryMeterStore = MeterStore & { stats(): StoreStats };

type Entry = {
	readonly key: string;
	readonly bytes: number;
	state: SlidingWindowState;
	expiresAtMilliseconds: number;
	position: number;
};

const expiryOf = (state: SlidingWindowState): number => {
	return (state.index + 2) * state.windowMilliseconds;
};

/**
 * In-process meter store, valid only for one long-lived process. It decides
 * with `slidingWindow`, so a key holds two counters and disappears two
 * intervals after its last counted request. Expired counters are dropped in
 * expiry order, each in O(log n).
 */
export function createMemoryMeterStore(
	options: MemoryMeterStoreOptions,
): MemoryMeterStore {
	const { maximumBytes } = options;

	if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
		throw new RangeError("maximumBytes must be a positive integer");
	}

	const entries = new Map<string, Entry>();
	const expiryOrder = createExpiryOrder<Entry>();
	let usedBytes = 0;
	let capacityRefusals = 0;

	const remove = (entry: Entry): void => {
		entries.delete(entry.key);
		expiryOrder.remove(entry);
		usedBytes -= entry.bytes;
	};

	const evictExpired = (now: number): void => {
		for (
			let earliest = expiryOrder.earliest();
			earliest !== undefined && !(now < earliest.expiresAtMilliseconds);
			earliest = expiryOrder.earliest()
		) {
			remove(earliest);
		}
	};

	return {
		async consume(input) {
			const now = Date.now();

			evictExpired(now);

			const existing = entries.get(input.key);
			const outcome = slidingWindow({
				state: existing?.state,
				nowMilliseconds: now,
				windowMilliseconds: input.windowMilliseconds,
				limit: input.limit,
				cost: input.cost,
			});
			const report = {
				used: Math.ceil(outcome.estimate),
				remaining: Math.max(0, Math.floor(input.limit - outcome.estimate)),
				resetsAtMilliseconds: outcome.retryAtMilliseconds,
			};

			if (!outcome.allowed) {
				return { allowed: false, ...report };
			}

			if (existing !== undefined) {
				expiryOrder.remove(existing);
				existing.state = outcome.state;
				existing.expiresAtMilliseconds = expiryOf(outcome.state);
				expiryOrder.add(existing);

				return { allowed: true, ...report };
			}

			const bytes = estimateBytes(input.key.length);

			if (usedBytes + bytes > maximumBytes) {
				capacityRefusals += 1;

				return {
					allowed: false,
					refusedForCapacity: true,
					used: input.limit,
					remaining: 0,
					resetsAtMilliseconds:
						expiryOrder.earliest()?.expiresAtMilliseconds ??
						outcome.retryAtMilliseconds,
				};
			}

			const entry: Entry = {
				key: input.key,
				bytes,
				state: outcome.state,
				expiresAtMilliseconds: expiryOf(outcome.state),
				position: 0,
			};

			entries.set(input.key, entry);
			expiryOrder.add(entry);
			usedBytes += bytes;

			return { allowed: true, ...report };
		},
		stats() {
			return {
				entries: entries.size,
				usedBytes,
				maximumBytes,
				capacityRefusals,
				evictions: 0,
			};
		},
	};
}
