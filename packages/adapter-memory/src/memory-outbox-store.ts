import type { OutboxRecord, OutboxStore } from "@vow-auth/core";

type Entry = {
	readonly id: string;
	readonly type: string;
	readonly payload: Readonly<Record<string, string>>;
	attempts: number;
	availableAtMilliseconds: number;
};

/** The in-process outbox store, with a view of the buried events for tests. */
export type MemoryOutboxStore = OutboxStore & {
	buried(): readonly OutboxRecord[];
	pending(): number;
};

/**
 * In-process outbox store for tests and single-instance development. It keeps
 * every event until it completes; it has no memory budget, because dropping an
 * event would lose a fact. It does not survive a restart.
 */
export function createMemoryOutboxStore(): MemoryOutboxStore {
	const entries = new Map<string, Entry>();
	const buriedRecords: OutboxRecord[] = [];

	const currentEntry = (record: OutboxRecord): Entry | undefined => {
		const entry = entries.get(record.id);

		return entry !== undefined && entry.attempts === record.attempts
			? entry
			: undefined;
	};

	return {
		async append(record) {
			if (entries.has(record.id)) {
				return;
			}

			entries.set(record.id, {
				id: record.id,
				type: record.type,
				payload: { ...record.payload },
				attempts: 0,
				availableAtMilliseconds: 0,
			});
		},
		async claim(input) {
			const now = Date.now();
			const claimed: OutboxRecord[] = [];

			for (const entry of entries.values()) {
				if (claimed.length >= input.limit) {
					break;
				}

				if (entry.availableAtMilliseconds <= now) {
					entry.attempts += 1;
					entry.availableAtMilliseconds = now + input.leaseMilliseconds;
					claimed.push({
						id: entry.id,
						type: entry.type,
						payload: { ...entry.payload },
						attempts: entry.attempts,
					});
				}
			}

			return claimed;
		},
		async complete(record) {
			if (currentEntry(record) !== undefined) {
				entries.delete(record.id);
			}
		},
		async release(record, retryDelayMilliseconds) {
			const entry = currentEntry(record);

			if (entry !== undefined) {
				entry.availableAtMilliseconds = Date.now() + retryDelayMilliseconds;
			}
		},
		async bury(record) {
			if (currentEntry(record) !== undefined) {
				entries.delete(record.id);
				buriedRecords.push(record);
			}
		},
		buried() {
			return buriedRecords;
		},
		pending() {
			return entries.size;
		},
	};
}
