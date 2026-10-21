import { createMintRegistry } from "./shared/mint-registry.js";

/** The two kinds of decision. */
export const DECISION_KINDS = { allow: "allow", deny: "deny" } as const;

/** Why a decision is a deny. */
export const DENY_REASONS = {
	notAllowed: "not-allowed",
	policyError: "policy-error",
} as const;

export type DenyReason = (typeof DENY_REASONS)[keyof typeof DENY_REASONS];

/** Verdict of a policy evaluation. Only `allow` can be turned into a session. */
export type Decision =
	| {
			readonly kind: typeof DECISION_KINDS.allow;
			readonly subject: string;
	  }
	| {
			readonly kind: typeof DECISION_KINDS.deny;
			readonly reason: DenyReason;
	  };

type AllowDecision = Extract<Decision, { kind: typeof DECISION_KINDS.allow }>;

const ALLOW_VERDICT = "allow";

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
		return { kind: DECISION_KINDS.deny, reason: DENY_REASONS.policyError };
	}

	if (verdict !== ALLOW_VERDICT) {
		return { kind: DECISION_KINDS.deny, reason: DENY_REASONS.notAllowed };
	}

	return mintedAllowDecisions.mint(
		Object.freeze({ kind: DECISION_KINDS.allow, subject }),
	);
}

export const isMintedAllow = mintedAllowDecisions.has;
