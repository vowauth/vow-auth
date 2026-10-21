import { own } from "../shared/own.js";
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

const isPositiveInteger = (value: number): boolean => {
	return Number.isInteger(value) && value > 0;
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

	for (const [name, value] of [
		["batchSize", batchSize],
		["maximumAttempts", maximumAttempts],
	] as const) {
		if (!isPositiveInteger(value)) {
			throw new RangeError(`${name} must be a positive integer`);
		}
	}

	for (const [name, value] of [
		["leaseMilliseconds", leaseMilliseconds],
		["retryDelayMilliseconds", retryDelayMilliseconds],
	] as const) {
		if (!Number.isFinite(value) || value <= 0) {
			throw new RangeError(`${name} must be a positive finite number`);
		}
	}

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

						return "buried";
					}

					try {
						await handler(record);
					} catch {
						if (record.attempts >= maximumAttempts) {
							await store.bury(record);

							return "buried";
						}

						await store.release(record, retryDelayMilliseconds);

						return "retried";
					}

					await store.complete(record);

					return "completed";
				}),
			);

			return {
				completed: outcomes.filter((outcome) => outcome === "completed").length,
				retried: outcomes.filter((outcome) => outcome === "retried").length,
				buried: outcomes.filter((outcome) => outcome === "buried").length,
			};
		},
	};
}
