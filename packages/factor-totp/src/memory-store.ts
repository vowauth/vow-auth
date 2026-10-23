import { storeFullError } from "@vow-auth/core";
import type { TotpRecord, TotpStore } from "./store.js";

/** Options of the in-process store. */
export type MemoryTotpStoreOptions = {
	/** The most subjects it holds; a new subject over it is refused with a store full error, and no record is ever dropped to make room. */
	readonly maximumRecords: number;
};

const keyOf = (tenant: string, subject: string): string =>
	JSON.stringify([tenant, subject]);

/**
 * In-process store for tests and for a single long-lived server. Records are
 * copied on the way in and out, like a networked store.
 */
export function createMemoryTotpStore(
	options: MemoryTotpStoreOptions,
): TotpStore {
	const { maximumRecords } = options;

	if (!Number.isSafeInteger(maximumRecords) || maximumRecords <= 0) {
		throw new RangeError("maximumRecords must be a positive integer");
	}

	const records = new Map<string, TotpRecord>();

	return {
		async find(tenant, subject) {
			const record = records.get(keyOf(tenant, subject));

			return record === undefined
				? undefined
				: { ...record, backupCodeHashes: [...record.backupCodeHashes] };
		},
		async save(tenant, subject, record) {
			const key = keyOf(tenant, subject);

			if (!records.has(key) && records.size >= maximumRecords) {
				throw storeFullError("The TOTP store is full");
			}

			records.set(key, {
				...record,
				backupCodeHashes: [...record.backupCodeHashes],
			});
		},
		async advance(tenant, subject, step) {
			const key = keyOf(tenant, subject);
			const record = records.get(key);

			if (record === undefined || step <= record.lastStep) {
				return false;
			}

			records.set(key, { ...record, lastStep: step });

			return true;
		},
		async spendBackupCode(tenant, subject, hash) {
			const key = keyOf(tenant, subject);
			const record = records.get(key);

			if (record === undefined || !record.backupCodeHashes.includes(hash)) {
				return false;
			}

			records.set(key, {
				...record,
				backupCodeHashes: record.backupCodeHashes.filter(
					(candidate) => candidate !== hash,
				),
			});

			return true;
		},
		async remove(tenant, subject) {
			return records.delete(keyOf(tenant, subject));
		},
	};
}
