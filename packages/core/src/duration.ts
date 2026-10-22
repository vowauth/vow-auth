import { ERROR_CODES } from "./errors.js";
import { fail, type Result, succeed } from "./result.js";
import { createMintRegistry } from "./shared/mint-registry.js";

const DURATION = Symbol("duration");

/**
 * A length of time the core has checked: a positive, finite number of
 * milliseconds. Anything that lives for a while (a token, a sealed value) takes
 * a `Duration` instead of a number, so a wrong value is caught where the
 * duration is defined, never when somebody signs in. Only `defineDuration`
 * creates one; the brand is a symbol nobody else can name.
 */
export type Duration = {
	readonly milliseconds: number;
	readonly [DURATION]: true;
};

const durations = createMintRegistry<Duration>();

/**
 * Checks a number of milliseconds and wraps it as a `Duration`. It never
 * throws: a number that is zero, negative, infinite or not a number is refused
 * with `invalid-request`.
 */
export const defineDuration = (milliseconds: number): Result<Duration> => {
	if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
		return fail(ERROR_CODES.invalidRequest);
	}

	return succeed(durations.mint({ milliseconds, [DURATION]: true }));
};

export const isDuration = (value: unknown): value is Duration => {
	return durations.has(value);
};
