import type { TokenRecord, TokenStore } from "@vow-auth/core";
import { estimateBytes } from "./estimate-bytes.js";
import { createExpiryOrder } from "./expiry-order.js";

/** Options of the in-process token store. */
export type MemoryTokenStoreOptions = {
	/**
	 * Memory budget in bytes. A record counts as 256 bytes plus 2 bytes per
	 * character of its hash and of its JSON form, which is above its real size
	 * in V8. A record that does not fit evicts the oldest records, so a flood
	 * of issued tokens shortens how long tokens live but never blocks issuing.
	 */
	readonly maximumBytes: number;
};

type Entry = {
	readonly hash: string;
	readonly serialized: string;
	readonly expiresAtMilliseconds: number;
	readonly bytes: number;
	position: number;
	older: Entry | undefined;
	newer: Entry | undefined;
};

const createInsertionOrder = () => {
	let oldest: Entry | undefined;
	let newest: Entry | undefined;

	return {
		oldest: (): Entry | undefined => oldest,
		add(entry: Entry): void {
			entry.older = newest;
			entry.newer = undefined;

			if (newest === undefined) {
				oldest = entry;
			} else {
				newest.newer = entry;
			}

			newest = entry;
		},
		remove(entry: Entry): void {
			if (entry.older === undefined) {
				oldest = entry.newer;
			} else {
				entry.older.newer = entry.newer;
			}

			if (entry.newer === undefined) {
				newest = entry.older;
			} else {
				entry.newer.older = entry.older;
			}
		},
	};
};

/**
 * In-process token store. Valid only when the same process issues and redeems
 * tokens: one long-lived server, not serverless and not several instances.
 * Records are serialized on write and parsed on read, like a networked store.
 * Every operation first evicts expired records in expiry order; a record that
 * does not fit into `maximumBytes` then evicts the oldest records. Each
 * eviction costs O(log n).
 */
export function createMemoryTokenStore(
	options: MemoryTokenStoreOptions,
): TokenStore {
	const { maximumBytes } = options;

	if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
		throw new RangeError("maximumBytes must be a positive integer");
	}

	const entries = new Map<string, Entry>();
	const expiryOrder = createExpiryOrder<Entry>();
	const insertionOrder = createInsertionOrder();
	let usedBytes = 0;

	const remove = (entry: Entry): void => {
		entries.delete(entry.hash);
		expiryOrder.remove(entry);
		insertionOrder.remove(entry);
		usedBytes -= entry.bytes;
	};

	const evictExpired = (): void => {
		const current = Date.now();

		for (
			let earliest = expiryOrder.earliest();
			earliest !== undefined && !(current < earliest.expiresAtMilliseconds);
			earliest = expiryOrder.earliest()
		) {
			remove(earliest);
		}
	};

	const evictOldestUntilFits = (bytes: number): void => {
		for (
			let oldest = insertionOrder.oldest();
			oldest !== undefined && usedBytes + bytes > maximumBytes;
			oldest = insertionOrder.oldest()
		) {
			remove(oldest);
		}
	};

	return {
		async put(hash, record) {
			if (!Number.isFinite(record.expiresAtMilliseconds)) {
				throw new RangeError("expiresAtMilliseconds must be a finite number");
			}

			const serialized = JSON.stringify(record);
			const bytes = estimateBytes(hash.length + serialized.length);

			if (bytes > maximumBytes) {
				throw new RangeError("A token record is larger than maximumBytes");
			}

			evictExpired();

			const existing = entries.get(hash);

			if (existing !== undefined) {
				remove(existing);
			}

			evictOldestUntilFits(bytes);

			const entry: Entry = {
				hash,
				serialized,
				expiresAtMilliseconds: record.expiresAtMilliseconds,
				bytes,
				position: 0,
				older: undefined,
				newer: undefined,
			};

			entries.set(hash, entry);
			expiryOrder.add(entry);
			insertionOrder.add(entry);
			usedBytes += bytes;
		},
		async take(hash) {
			evictExpired();

			const entry = entries.get(hash);

			if (entry === undefined) {
				return undefined;
			}

			remove(entry);

			const record: TokenRecord = JSON.parse(entry.serialized);

			return record;
		},
	};
}
