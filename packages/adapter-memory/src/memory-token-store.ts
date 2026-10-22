import {
	type StoreStats,
	storeFullError,
	type TokenRecord,
	type TokenStore,
} from "@vow-auth/core";
import { estimateBytes } from "./estimate-bytes.js";
import { createExpiryOrder } from "./expiry-order.js";

/** Options of the in-process token store. */
export type MemoryTokenStoreOptions = {
	/**
	 * Memory budget in bytes. A record counts as 256 bytes plus 2 bytes per
	 * character of its hash and of its JSON form, which is above its real size
	 * in V8. A record that does not fit after expired records are dropped is
	 * refused with a store full error; a live record is never dropped to make
	 * room, so nobody can push another person's pending token out by flooding.
	 */
	readonly maximumBytes: number;
};

/** The token store, with the numbers an operator watches. */
export type MemoryTokenStore = TokenStore & { stats(): StoreStats };

type Entry = {
	readonly hash: string;
	readonly serialized: string;
	readonly expiresAtMilliseconds: number;
	readonly bytes: number;
	position: number;
};

/**
 * In-process token store. Valid only when the same process issues and redeems
 * tokens: one long-lived server, not serverless and not several instances.
 * Records are serialized on write and parsed on read, like a networked store.
 * Every operation first drops expired records in expiry order, each in
 * O(log n). When a record still does not fit, `put` throws a store full error
 * and nothing is evicted.
 */
export function createMemoryTokenStore(
	options: MemoryTokenStoreOptions,
): MemoryTokenStore {
	const { maximumBytes } = options;

	if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
		throw new RangeError("maximumBytes must be a positive integer");
	}

	const entries = new Map<string, Entry>();
	const expiryOrder = createExpiryOrder<Entry>();
	let usedBytes = 0;
	let capacityRefusals = 0;

	const remove = (entry: Entry): void => {
		entries.delete(entry.hash);
		expiryOrder.remove(entry);
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
			const reclaimed = existing?.bytes ?? 0;

			if (usedBytes - reclaimed + bytes > maximumBytes) {
				capacityRefusals += 1;

				throw storeFullError("The token store has no room for one more record");
			}

			if (existing !== undefined) {
				remove(existing);
			}

			const entry: Entry = {
				hash,
				serialized,
				expiresAtMilliseconds: record.expiresAtMilliseconds,
				bytes,
				position: 0,
			};

			entries.set(hash, entry);
			expiryOrder.add(entry);
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
