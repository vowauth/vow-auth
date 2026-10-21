import type { MeterStore } from "@vow-auth/core";
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

type Entry = {
	readonly key: string;
	readonly bytes: number;
	used: number;
	expiresAtMilliseconds: number;
	position: number;
};

/**
 * In-process meter store, valid only for one long-lived process. Each counter
 * is a fixed window that starts at its first counted request. Expired counters
 * are dropped in expiry order, each in O(log n).
 */
export function createMemoryMeterStore(
	options: MemoryMeterStoreOptions,
): MeterStore {
	const { maximumBytes } = options;

	if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
		throw new RangeError("maximumBytes must be a positive integer");
	}

	const entries = new Map<string, Entry>();
	const expiryOrder = createExpiryOrder<Entry>();
	let usedBytes = 0;

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

			if (existing !== undefined) {
				const fits = existing.used + input.cost <= input.limit;

				if (fits) {
					existing.used += input.cost;
				}

				return {
					allowed: fits,
					used: existing.used,
					remaining: Math.max(0, input.limit - existing.used),
					resetsAtMilliseconds: existing.expiresAtMilliseconds,
				};
			}

			const bytes = estimateBytes(input.key.length);
			const resetsAtMilliseconds = now + input.windowMilliseconds;

			if (usedBytes + bytes > maximumBytes || input.cost > input.limit) {
				return {
					allowed: false,
					used: input.limit,
					remaining: 0,
					resetsAtMilliseconds:
						expiryOrder.earliest()?.expiresAtMilliseconds ??
						resetsAtMilliseconds,
				};
			}

			const entry: Entry = {
				key: input.key,
				bytes,
				used: input.cost,
				expiresAtMilliseconds: resetsAtMilliseconds,
				position: 0,
			};

			entries.set(input.key, entry);
			expiryOrder.add(entry);
			usedBytes += bytes;

			return {
				allowed: true,
				used: entry.used,
				remaining: input.limit - entry.used,
				resetsAtMilliseconds,
			};
		},
	};
}
