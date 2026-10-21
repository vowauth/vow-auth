import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import type { MeterReading, MeterStore } from "./meter-store.js";

/** Whose requests are counted, and what they are asked for. */
export type MeterScope = {
	readonly tenant: string;
	readonly actor: string;
	readonly resource: string;
};

/** At most `limit` units per window of `windowMilliseconds`. */
export type MeterRule = {
	readonly limit: number;
	readonly windowMilliseconds: number;
};

/** Why a request was refused and when to ask again. */
export type MeterRefusal = {
	readonly code: typeof ERROR_CODES.rateLimited;
	readonly resetsAtMilliseconds: number;
};

/** Counts requests against limits that all instances share. */
export type Meter = {
	consume(
		scope: MeterScope,
		rule: MeterRule,
		cost?: number,
	): Promise<Result<MeterReading, MeterRefusal>>;
};

/** Options for creating the meter. */
export type MeterOptions = {
	readonly store: MeterStore;
	readonly audit?: AuditSink | undefined;
};

const keyOf = (scope: MeterScope): string => {
	return `{${encodeURIComponent(scope.tenant)}}:meter:${encodeURIComponent(scope.resource)}:${encodeURIComponent(scope.actor)}`;
};

const isPositiveInteger = (value: number): boolean => {
	return Number.isSafeInteger(value) && value > 0;
};

/**
 * Creates the meter. The caller owns the numbers: a rule that is not a
 * positive limit over a positive window, or a cost that is not a positive
 * whole number within the limit, is a programming error and throws. A request
 * over the limit is refused with the time the window ends and recorded in the
 * audit; requests within the limit are not recorded, they are the hot path.
 * If the store fails, so does the call: nothing is let through on a guess.
 */
export function createMeter(options: MeterOptions): Meter {
	const { store, audit } = options;

	return {
		async consume(scope, rule, cost = 1) {
			if (
				!isPositiveInteger(rule.limit) ||
				!Number.isFinite(rule.windowMilliseconds) ||
				rule.windowMilliseconds <= 0
			) {
				throw new RangeError(
					"limit must be a positive integer and windowMilliseconds a positive finite number",
				);
			}

			if (!isPositiveInteger(cost) || cost > rule.limit) {
				throw new RangeError(
					"cost must be a positive integer, at most the limit",
				);
			}

			const outcome = await store.consume({
				key: keyOf(scope),
				cost,
				limit: rule.limit,
				windowMilliseconds: rule.windowMilliseconds,
			});

			if (!outcome.allowed) {
				await report(audit, {
					event: AUDIT_EVENTS.meterConsume,
					outcome: AUDIT_OUTCOMES.refusal,
					reason: AUDIT_REASONS.limitExceeded,
					tenant: scope.tenant,
					subject: scope.actor,
					detail: {
						resource: scope.resource,
						limit: String(rule.limit),
						used: String(outcome.used),
					},
				});

				return fail({
					code: ERROR_CODES.rateLimited,
					resetsAtMilliseconds: outcome.resetsAtMilliseconds,
				});
			}

			return succeed({
				used: outcome.used,
				remaining: outcome.remaining,
				resetsAtMilliseconds: outcome.resetsAtMilliseconds,
			});
		},
	};
}
