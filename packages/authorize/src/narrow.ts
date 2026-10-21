import {
	type Ability,
	buildAbility,
	type CheckedRule,
	type ResourceMap,
	RuleEffect,
} from "@vetojs/core";
import { ERROR_CODES, fail, type Result, succeed } from "@vow-auth/core";

/**
 * Builds the ability of someone who acts for another: the delegator's rules
 * plus extra denies. Nothing else can be added, so what the delegate may do is
 * always a subset of what the delegator may do, and every restriction of the
 * delegator still holds. A rule that is not a deny refuses the delegation as a
 * whole. The delegate is built from the delegator's own rules, not from a copy
 * of their verdicts, so both answer through the same engine.
 */
export function narrow<AC extends ResourceMap>(
	ac: AC,
	delegator: Ability<AC>,
	denies: readonly CheckedRule[],
): Result<Ability<AC>> {
	if (!denies.every((rule) => rule.effect === RuleEffect.Deny)) {
		return fail(ERROR_CODES.invalidDelegation);
	}

	return succeed(buildAbility(ac, [...delegator.rules, ...denies]));
}
