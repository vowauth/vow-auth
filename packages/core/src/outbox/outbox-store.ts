/** A domain fact to tell the outside world about: a mail to send, a webhook to call. */
export type DomainEvent = {
	readonly type: string;
	readonly payload?: Readonly<Record<string, string>>;
};

/** An event as stored: it has an id for deduplication and counts its claims. */
export type OutboxRecord = {
	readonly id: string;
	readonly type: string;
	readonly payload: Readonly<Record<string, string>>;
	readonly attempts: number;
};

/** What a worker takes from the outbox in one call. */
export type ClaimInput = {
	readonly limit: number;
	readonly leaseMilliseconds: number;
};

/**
 * Storage port for the outbox.
 *
 * - `append` must commit together with the change that caused the event, in
 *   the same transaction, or the event is lost or invented when they diverge.
 * - `claim` hides the events it returns from other workers for the lease and
 *   increments their `attempts`. An event whose lease ran out is claimable
 *   again, so a crashed worker loses nothing.
 * - `complete`, `release` and `bury` act on a claimed record and must be
 *   ignored when its `attempts` no longer match the stored ones: a worker
 *   whose lease expired cannot undo a newer claim.
 * - The store reads its own clock, as the other stores do.
 */
export type OutboxStore = {
	append(record: Omit<OutboxRecord, "attempts">): Promise<void>;
	claim(input: ClaimInput): Promise<readonly OutboxRecord[]>;
	complete(record: OutboxRecord): Promise<void>;
	release(record: OutboxRecord, retryDelayMilliseconds: number): Promise<void>;
	bury(record: OutboxRecord): Promise<void>;
};
