import type { EpochStore } from "@vow-auth/core";
import { estimateBytes } from "./estimate-bytes.js";
import { createExpiryOrder } from "./expiry-order.js";

/** Options of the in-process epoch store. */
export type MemoryEpochStoreOptions = {
	/**
	 * Memory budget in bytes. A revocation counts as 256 bytes plus 2 bytes per
	 * character of its key. A revocation that does not fit makes the store
	 * forget every stored revocation and raise its floor above every stamp, which
	 * revokes every token issued so far: overflow logs everyone out instead of
	 * reviving a revoked token.
	 */
	readonly maximumBytes: number;
};

type Entry = {
	readonly key: string;
	readonly stamp: number;
	readonly expiresAtMilliseconds: number;
	readonly bytes: number;
	position: number;
};

/**
 * In-process epoch store. Valid only for one long-lived process: revocations
 * are not shared between processes. It keeps nothing across a restart, so its
 * floor starts at the moment of creation: a key that was never revoked reads
 * as that moment instead of 0, and a restart revokes every token issued before
 * it instead of forgetting revocations. Every operation first evicts expired
 * revocations in O(log n) each.
 */
export function createMemoryEpochStore(
	options: MemoryEpochStoreOptions,
): EpochStore {
	const { maximumBytes } = options;

	if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
		throw new RangeError("maximumBytes must be a positive integer");
	}

	const entries = new Map<string, Entry>();
	let expiryOrder = createExpiryOrder<Entry>();
	let floor = Date.now();
	let highestStamp = floor;
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

	const stampOf = (key: string): number => {
		return entries.get(key)?.stamp ?? floor;
	};

	const forgetEverything = (now: number): number => {
		entries.clear();
		expiryOrder = createExpiryOrder<Entry>();
		usedBytes = 0;
		floor = Math.max(highestStamp + 1, now);
		highestStamp = floor;

		return floor;
	};

	return {
		async read(keys) {
			const now = Date.now();
			evictExpired(now);

			return { now, stamps: keys.map(stampOf) };
		},
		async revoke(key, timeToLiveMilliseconds) {
			const now = Date.now();
			evictExpired(now);

			const stamp = Math.max(stampOf(key) + 1, now);
			const bytes = estimateBytes(key.length);
			const existing = entries.get(key);

			if (existing !== undefined) {
				remove(existing);
			}

			if (usedBytes + bytes > maximumBytes) {
				return forgetEverything(now);
			}

			const entry: Entry = {
				key,
				stamp,
				expiresAtMilliseconds: now + timeToLiveMilliseconds,
				bytes,
				position: 0,
			};
			entries.set(key, entry);
			expiryOrder.add(entry);
			usedBytes += bytes;
			highestStamp = Math.max(highestStamp, stamp);

			return stamp;
		},
	};
}
