import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import type { Meter, MeterRefusal, MeterRule, MeterScope } from "./meter.js";

/**
 * The explicit choice of having no limit. Every place that does something an
 * anonymous caller can repeat at a cost (a sign in, a link to send) asks for a
 * limit, and the answer must be written down: a limiter, or this.
 */
export const NO_LIMIT = "off";

/** Decides whether an attempt may go on. It counts the attempt, as `meter.consume` does. */
export type Limiter<Input> = (
	input: Input,
) => Promise<Result<undefined, MeterRefusal>>;

/** A limiter, or the explicit choice of none. */
export type Limit<Input> = Limiter<Input> | typeof NO_LIMIT;

/** Options for creating a limiter. */
export type LimiterOptions<Input> = {
	readonly meter: Pick<Meter, "consume">;
	/** Made once with `defineMeterRule`; every scope is counted against it. */
	readonly rule: MeterRule;
	/**
	 * What to count for this attempt, such as the address of the client and the
	 * address a link goes to. Every scope must be within the limit, and each one
	 * is counted on its own, like independent rules. Name the resource per
	 * action so that a sign in and a link request do not share a counter.
	 */
	readonly scopes: (input: Input) => readonly MeterScope[];
};

/**
 * Creates a limiter on a meter. Define it once and give the same one to every
 * handler and factor that needs it. The first scope over its limit refuses the
 * attempt with the refusal of the meter, so the caller can say when to try
 * again; a meter that cannot count refuses too, never lets the attempt pass.
 */
export function createLimiter<Input>(
	options: LimiterOptions<Input>,
): Limiter<Input> {
	return async (input) => {
		for (const scope of options.scopes(input)) {
			const consumed = await options.meter.consume(scope, options.rule);

			if (!consumed.ok) {
				return fail(consumed.error);
			}
		}

		return succeed(undefined);
	};
}

/** Throws a `TypeError` when a limit is neither a limiter nor `"off"`, so a forgotten option stops the start. */
export function assertLimit(name: string, limit: unknown): void {
	if (limit !== NO_LIMIT && typeof limit !== "function") {
		throw new TypeError(
			`${name} must be a limiter, or "${NO_LIMIT}" to say that there is no limit`,
		);
	}
}

/** Runs a limit: `"off"` lets the attempt pass, a limiter decides. Anything else is refused. */
export async function applyLimit<Input>(
	limit: Limit<Input>,
	input: Input,
): Promise<Result<undefined, MeterRefusal>> {
	if (limit === NO_LIMIT) {
		return succeed(undefined);
	}

	return typeof limit === "function"
		? limit(input)
		: fail({ code: ERROR_CODES.invalidRequest });
}
