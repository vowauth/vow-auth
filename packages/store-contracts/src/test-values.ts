import {
	type Duration,
	defineDuration,
	defineMeterRule,
	type MeterRule,
} from "@vow-auth/core";

/** A `Duration` for a test that knows its number is valid. */
export const durationOf = (milliseconds: number): Duration => {
	const defined = defineDuration(milliseconds);

	if (!defined.ok) {
		throw new Error(`${milliseconds} is not a valid duration`);
	}

	return defined.value;
};

/** A `MeterRule` for a test that knows its numbers are valid. */
export const meterRuleOf = (input: {
	readonly limit: number;
	readonly windowMilliseconds: number;
}): MeterRule => {
	const defined = defineMeterRule(input);

	if (!defined.ok) {
		throw new Error(`${JSON.stringify(input)} is not a valid meter rule`);
	}

	return defined.value;
};
