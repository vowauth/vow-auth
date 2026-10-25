/** What the store keeps for one account. The secret is sealed: the store never holds it in the clear. */
export type TotpRecord = {
	readonly sealedSecret: string;
	/** `false` until the person has typed a first code from their app. */
	readonly confirmed: boolean;
	/** The latest time step whose code was accepted, `-1` before any. */
	readonly lastStep: number;
	/** SHA-256 of each backup code that is still unused. */
	readonly backupCodeHashes: readonly string[];
};

/**
 * Storage port of the factor. An adapter must make `advance` and
 * `spendBackupCode` atomic: of any number of concurrent calls for one step or
 * one code, exactly one is told `true`. A read followed by a write is not
 * atomic, and without these two guarantees a code can be used twice.
 */
export type TotpStore = {
	find(account: string): Promise<TotpRecord | undefined>;
	/** Replaces the record of the account, or creates it. */
	save(account: string, record: TotpRecord): Promise<void>;
	/** Raises `lastStep` to `step` and says `true`, only when `step` is above it; `false` when there is no record or the step is not new. */
	advance(account: string, step: number): Promise<boolean>;
	/** Removes the hash and says `true`; `false` when the record does not hold it. */
	spendBackupCode(account: string, hash: string): Promise<boolean>;
	/** Deletes the record; `false` when there was none. */
	remove(account: string): Promise<boolean>;
};
