import { isPlainObject } from "./shared/is-plain-object.js";

/** Verdict of a policy evaluation. Only `allow` can be turned into a session. */
export type Decision =
	| { readonly kind: "allow"; readonly subject: string }
	| { readonly kind: "deny"; readonly reason: string };

const mintedAllowDecisions = new WeakSet();

/**
 * Evaluates a policy for a subject. Only the exact string `"allow"` is a
 * permission; any other value, including `"Allow"`, `undefined` or a thrown
 * error, yields a deny.
 */
export function evaluatePolicy(
	subject: string,
	policy: (subject: string) => unknown,
): Decision {
	let verdict: unknown;

	try {
		verdict = policy(subject);
	} catch {
		return { kind: "deny", reason: "policy-error" };
	}

	if (verdict !== "allow") {
		return { kind: "deny", reason: "not-allowed" };
	}

	const decision: Decision = Object.freeze({ kind: "allow", subject });
	mintedAllowDecisions.add(decision);

	return decision;
}

export const isMintedAllow = (
	value: unknown,
): value is Decision & { kind: "allow" } => {
	return isPlainObject(value) && mintedAllowDecisions.has(value);
};
