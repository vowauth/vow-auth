import { storeFullError } from "@vow-auth/core";
import type { TotpRecord, TotpStore } from "./store.js";

/** Options of the in-process store. */
export type MemoryTotpStoreOptions = {
	/** The most accounts it holds; a new account over it is refused with a store full error, and no record is ever dropped to make room. */
	readonly maximumRecords: number;
};

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
		async find(account) {
			const record = records.get(account);

			return record === undefined
				? undefined
				: { ...record, backupCodeHashes: [...record.backupCodeHashes] };
		},
		async save(account, record) {
			if (!records.has(account) && records.size >= maximumRecords) {
				throw storeFullError("The TOTP store is full");
			}

			records.set(account, {
				...record,
				backupCodeHashes: [...record.backupCodeHashes],
			});
		},
		async advance(account, step) {
			const record = records.get(account);

			if (record === undefined || step <= record.lastStep) {
				return false;
			}

			records.set(account, { ...record, lastStep: step });

			return true;
		},
		async spendBackupCode(account, hash) {
			const record = records.get(account);

			if (record === undefined || !record.backupCodeHashes.includes(hash)) {
				return false;
			}

			records.set(account, {
				...record,
				backupCodeHashes: record.backupCodeHashes.filter(
					(candidate) => candidate !== hash,
				),
			});

			return true;
		},
		async remove(account) {
			return records.delete(account);
		},
	};
}
