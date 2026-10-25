import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { createMintRegistry } from "../shared/mint-registry.js";
import type {
	MeterReading,
	MeterStore,
	MeterStoreResult,
} from "./meter-store.js";

/** Whose requests are counted, and what they are asked for. */
export type MeterScope = {
	readonly tenant: string;
	readonly actor: string;
	readonly resource: string;
};

const METER_RULE = Symbol("meter-rule");

/**
 * At most `limit` units per window of `windowMilliseconds`. Only
 * `defineMeterRule` creates one, so a rule the meter accepts has been checked
 * and can never make a request throw.
 */
export type MeterRule = {
	readonly limit: number;
	readonly windowMilliseconds: number;
	readonly [METER_RULE]: true;
};

const meterRules = createMintRegistry<MeterRule>();

const isPositiveInteger = (value: number): boolean => {
	return Number.isSafeInteger(value) && value > 0;
};

/**
 * Checks a limit and a window and wraps them as a `MeterRule`. It never
 * throws: a limit or window that is not a positive integer is refused with
 * `invalid-request`. Define a rule once, where the application starts, and
 * handle the refusal there.
 */
export const defineMeterRule = (input: {
	readonly limit: number;
	readonly windowMilliseconds: number;
}): Result<MeterRule> => {
	const { limit, windowMilliseconds } = input;

	if (!isPositiveInteger(limit) || !isPositiveInteger(windowMilliseconds)) {
		return fail(ERROR_CODES.invalidRequest);
	}

	return succeed(
		meterRules.mint({ limit, windowMilliseconds, [METER_RULE]: true }),
	);
};

/**
 * Why a request was refused: over the limit, with the moment to ask again; a
 * rule or cost that is not valid; or (only through a remote client) because
 * the service could not be reached.
 */
export type MeterRefusal =
	| {
			readonly code: typeof ERROR_CODES.rateLimited;
			readonly resetsAtMilliseconds: number;
	  }
	| { readonly code: typeof ERROR_CODES.invalidRequest }
	| { readonly code: typeof ERROR_CODES.unavailable };

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

/**
 * Creates the meter. Requests are counted in a sliding window, as in
 * Cloudflare's rate limiting: the rate is the count of the current interval
 * plus the count of the previous one, weighted by how much of it still falls
 * into the last `windowMilliseconds`. The rule is checked when it is
 * defined (`defineMeterRule`), so only the cost is checked per call: a cost
 * that is not a positive whole number within the limit, or a rule that did not
 * come from `defineMeterRule`, is refused with `invalid-request` and counts
 * nothing. A refused request counts nothing; it is refused with the earliest moment it
 * would pass and recorded in the audit, with the reason `capacity` when the
 * store had no room for the key; requests within the limit are not recorded,
 * they are the hot path. If the store fails, so does the call: nothing is let
 * through on a guess.
 */
export function createMeter(options: MeterOptions): Meter {
	const { store, audit } = options;

	const decide = async (
		scope: MeterScope,
		rule: MeterRule,
		cost: number,
	): Promise<Result<MeterStoreResult, MeterRefusal>> => {
		if (
			!meterRules.has(rule) ||
			!isPositiveInteger(cost) ||
			cost > rule.limit
		) {
			return fail({ code: ERROR_CODES.invalidRequest });
		}

		return succeed(
			await store.consume({
				key: keyOf(scope),
				cost,
				limit: rule.limit,
				windowMilliseconds: rule.windowMilliseconds,
			}),
		);
	};

	const record = (
		scope: MeterScope,
		rule: MeterRule,
		answer: MeterStoreResult,
	) => {
		return report(audit, {
			event: AUDIT_EVENTS.meterConsume,
			outcome: AUDIT_OUTCOMES.refusal,
			reason:
				answer.refusedForCapacity === true
					? AUDIT_REASONS.capacity
					: AUDIT_REASONS.limitExceeded,
			tenant: scope.tenant,
			subject: scope.actor,
			detail: {
				resource: scope.resource,
				limit: String(rule.limit),
				used: String(answer.used),
			},
		});
	};

	return {
		async consume(scope, rule, cost = 1) {
			const decided = await decide(scope, rule, cost);

			if (!decided.ok) {
				return fail(decided.error);
			}

			const answer = decided.value;

			if (!answer.allowed) {
				await record(scope, rule, answer);

				return fail({
					code: ERROR_CODES.rateLimited,
					resetsAtMilliseconds: answer.resetsAtMilliseconds,
				});
			}

			return succeed({
				used: answer.used,
				remaining: answer.remaining,
				resetsAtMilliseconds: answer.resetsAtMilliseconds,
			});
		},
	};
}
