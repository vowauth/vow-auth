import { createMintRegistry } from "./shared/mint-registry.js";

/** Verdict of a policy evaluation. Only `allow` can be turned into a session. */
export type Decision =
	| { readonly kind: "allow"; readonly subject: string }
	| { readonly kind: "deny"; readonly reason: string };

type AllowDecision = Extract<Decision, { kind: "allow" }>;

const mintedAllowDecisions = createMintRegistry<AllowDecision>();

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

	return mintedAllowDecisions.mint(Object.freeze({ kind: "allow", subject }));
}

export const isMintedAllow = mintedAllowDecisions.has;
