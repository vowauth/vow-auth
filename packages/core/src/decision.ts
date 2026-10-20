/** Verdict of a policy evaluation. Only `allow` can be turned into a session. */
export type Decision =
	| { readonly kind: "allow"; readonly subject: string }
	| { readonly kind: "deny"; readonly reason: string };

const mintedAllowDecisions = new WeakSet<Decision>();

/**
 * Evaluates a policy for a subject. The policy may be synchronous or
 * asynchronous. Only the exact string `"allow"` is a permission; any other
 * value, including `"Allow"`, `undefined`, a thrown error or a rejected
 * promise, yields a deny.
 */
export async function evaluatePolicy(
	subject: string,
	policy: (subject: string) => unknown,
): Promise<Decision> {
	let verdict: unknown;

	try {
		verdict = await policy(subject);
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
	return mintedAllowDecisions.has(value as Decision);
};
