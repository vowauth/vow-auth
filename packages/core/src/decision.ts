import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	type AuditSink,
	report,
} from "./audit.js";
import { createMintRegistry } from "./shared/mint-registry.js";
import { own } from "./shared/own.js";
import type { ValueOf } from "./shared/value-of.js";

/** The two kinds of decision. */
export const DECISION_KINDS = { allow: "allow", deny: "deny" } as const;

/** Why a decision is a deny. */
export const DENY_REASONS = {
	notAllowed: "not-allowed",
	policyError: "policy-error",
} as const;

export type DenyReason = ValueOf<typeof DENY_REASONS>;

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

/** Options of `evaluatePolicy`. */
export type EvaluatePolicyOptions = {
	readonly audit?: AuditSink | undefined;
	/** Only for the audit record: the tenant the decision is about. */
	readonly tenant?: string;
};

type AllowDecision = Extract<Decision, { kind: typeof DECISION_KINDS.allow }>;

const ALLOW_VERDICT = "allow";

const mintedAllowDecisions = createMintRegistry<AllowDecision>();

const judge = async (
	subject: string,
	policy: (subject: string) => unknown,
): Promise<DenyReason | undefined> => {
	let verdict: unknown;

	try {
		verdict = await policy(subject);
	} catch {
		return DENY_REASONS.policyError;
	}

	return verdict === ALLOW_VERDICT ? undefined : DENY_REASONS.notAllowed;
};

/**
 * Evaluates a policy for a subject. The policy may be synchronous or
 * asynchronous. Only the exact string `"allow"` is a permission; any other
 * value, including `"Allow"`, `undefined`, a thrown error or a rejected
 * promise, yields a deny. An allow is recorded in the audit before it is
 * returned: if the sink throws, there is no decision.
 */
export async function evaluatePolicy(
	subject: string,
	policy: (subject: string) => unknown,
	options: EvaluatePolicyOptions = {},
): Promise<Decision> {
	const denyReason = await judge(subject, policy);

	await report(own(options, "audit"), {
		event: AUDIT_EVENTS.policyEvaluate,
		outcome:
			denyReason === undefined
				? AUDIT_OUTCOMES.success
				: AUDIT_OUTCOMES.refusal,
		reason: denyReason ?? DECISION_KINDS.allow,
		tenant: own(options, "tenant") ?? "",
		subject,
		detail: {},
	});

	if (denyReason !== undefined) {
		return { kind: DECISION_KINDS.deny, reason: denyReason };
	}

	return mintedAllowDecisions.mint({ kind: DECISION_KINDS.allow, subject });
}

export const isMintedAllow = mintedAllowDecisions.has;
