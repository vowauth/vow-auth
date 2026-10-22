import { own } from "../shared/own.js";
import type { ValueOf } from "../shared/value-of.js";
import type { OutboxRecord, OutboxStore } from "./outbox-store.js";

/** Handles one event. It may throw; a throw means try again later. */
export type OutboxHandler = (event: OutboxRecord) => Promise<void>;

/** Options of the outbox worker. */
export type OutboxWorkerOptions = {
	readonly store: OutboxStore;
	readonly handlers: Readonly<Record<string, OutboxHandler>>;
	readonly batchSize: number;
	/** How long a claimed event stays hidden from other workers; longer than the slowest handler. */
	readonly leaseMilliseconds: number;
	readonly retryDelayMilliseconds: number;
	/** After this many claims an event that keeps failing is buried instead of retried. */
	readonly maximumAttempts: number;
};

/** What one run did. */
export type OutboxRunSummary = {
	readonly completed: number;
	readonly retried: number;
	readonly buried: number;
};

/** Delivers outbox events to their handlers. Call `runOnce` from a queue consumer or a scheduler. */
export type OutboxWorker = {
	runOnce(): Promise<OutboxRunSummary>;
};

const RUN_OUTCOMES = {
	buried: "buried",
	completed: "completed",
	retried: "retried",
} as const;

const requirePositiveInteger = (name: string, value: number): void => {
	if (!Number.isInteger(value) || value <= 0) {
		throw new RangeError(`${name} must be a positive integer`);
	}
};

const requirePositiveNumber = (name: string, value: number): void => {
	if (!Number.isFinite(value) || value <= 0) {
		throw new RangeError(`${name} must be a positive finite number`);
	}
};

/**
 * Creates the outbox worker. Handlers run after the request that emitted the
 * event, in isolation: one handler failing never affects another event. An
 * event without a handler is buried at once, so a typo cannot loop forever.
 */
export function createOutboxWorker(options: OutboxWorkerOptions): OutboxWorker {
	const {
		store,
		handlers,
		batchSize,
		leaseMilliseconds,
		retryDelayMilliseconds,
		maximumAttempts,
	} = options;

	requirePositiveInteger("batchSize", batchSize);
	requirePositiveInteger("maximumAttempts", maximumAttempts);
	requirePositiveNumber("leaseMilliseconds", leaseMilliseconds);
	requirePositiveNumber("retryDelayMilliseconds", retryDelayMilliseconds);

	return {
		async runOnce() {
			const claimed = await store.claim({
				limit: batchSize,
				leaseMilliseconds,
			});

			const outcomes = await Promise.all(
				claimed.map(async (record) => {
					const handler = own(handlers, record.type);

					if (handler === undefined) {
						await store.bury(record);

						return RUN_OUTCOMES.buried;
					}

					try {
						await handler(record);
					} catch {
						if (record.attempts >= maximumAttempts) {
							await store.bury(record);

							return RUN_OUTCOMES.buried;
						}

						await store.release(record, retryDelayMilliseconds);

						return RUN_OUTCOMES.retried;
					}

					await store.complete(record);

					return RUN_OUTCOMES.completed;
				}),
			);

			const countOf = (outcome: ValueOf<typeof RUN_OUTCOMES>): number => {
				return outcomes.filter((candidate) => candidate === outcome).length;
			};

			return {
				completed: countOf(RUN_OUTCOMES.completed),
				retried: countOf(RUN_OUTCOMES.retried),
				buried: countOf(RUN_OUTCOMES.buried),
			};
		},
	};
}
