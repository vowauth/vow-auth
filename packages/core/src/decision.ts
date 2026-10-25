import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "./audit.js";
import { createMintRegistry } from "./shared/mint-registry.js";
import { own } from "./shared/own.js";
import type { ValueOf } from "./shared/value-of.js";

/** The kinds of decision. */
export const DECISION_KINDS = {
	allow: "allow",
	deny: "deny",
	stepUp: "step-up",
} as const;

/** Why a decision is a deny. */
export const DENY_REASONS = {
	notAllowed: "not-allowed",
	policyError: "policy-error",
	stepUpUnavailable: "step-up-unavailable",
} as const;

export type DenyReason = ValueOf<typeof DENY_REASONS>;

/**
 * Verdict of a policy evaluation. Only `allow` can be turned into a session;
 * `step-up` asks for one more factor before any decision is made.
 */
export type Decision =
	| {
			readonly kind: typeof DECISION_KINDS.allow;
			readonly subject: string;
	  }
	| {
			readonly kind: typeof DECISION_KINDS.deny;
			readonly reason: DenyReason;
	  }
	| {
			readonly kind: typeof DECISION_KINDS.stepUp;
			readonly subject: string;
			readonly factor: string;
	  };

/** Options of `evaluatePolicy`. */
export type EvaluatePolicyOptions = {
	readonly audit?: AuditSink | undefined;
	/** Only for the audit record: the tenant the decision is about. */
	readonly tenant?: string;
	/**
	 * Whether a policy may ask for another factor. When it is not, a step-up
	 * verdict is a deny, so a flow that cannot continue never half-grants.
	 */
	readonly stepUpAllowed?: boolean;
	/** Only for the audit record: which policy decided, when a flow asks more than one. */
	readonly name?: string;
};

type AllowDecision = Extract<Decision, { kind: typeof DECISION_KINDS.allow }>;

const ALLOW_VERDICT = "allow";
const STEP_UP = Symbol("step-up");

/**
 * What a policy returns to ask for one more factor. Only `requireFactor`
 * creates one, so a policy cannot ask for a step-up by accident.
 */
export type StepUpVerdict = {
	readonly kind: typeof DECISION_KINDS.stepUp;
	readonly factor: string;
	readonly [STEP_UP]: true;
};

const mintedAllowDecisions = createMintRegistry<AllowDecision>();
const stepUpVerdicts = createMintRegistry<StepUpVerdict>();

/**
 * Returns the verdict that tells the sign-in flow the person has not proven
 * enough yet and must also pass the factor with this id. It never throws; a
 * factor id the flow does not know ends the sign-in with a refusal.
 */
export const requireFactor = (factor: string): StepUpVerdict => {
	return stepUpVerdicts.mint({
		kind: DECISION_KINDS.stepUp,
		factor,
		[STEP_UP]: true,
	});
};

type Judgement =
	| { readonly kind: typeof DECISION_KINDS.allow }
	| { readonly kind: typeof DECISION_KINDS.deny; readonly reason: DenyReason }
	| { readonly kind: typeof DECISION_KINDS.stepUp; readonly factor: string };

const judge = async (
	subject: string,
	policy: (subject: string) => unknown,
	stepUpAllowed: boolean,
): Promise<Judgement> => {
	let verdict: unknown;

	try {
		verdict = await policy(subject);
	} catch {
		return { kind: DECISION_KINDS.deny, reason: DENY_REASONS.policyError };
	}

	if (verdict === ALLOW_VERDICT) {
		return { kind: DECISION_KINDS.allow };
	}

	if (stepUpVerdicts.has(verdict)) {
		return stepUpAllowed && verdict.factor !== ""
			? { kind: DECISION_KINDS.stepUp, factor: verdict.factor }
			: { kind: DECISION_KINDS.deny, reason: DENY_REASONS.stepUpUnavailable };
	}

	return { kind: DECISION_KINDS.deny, reason: DENY_REASONS.notAllowed };
};

/**
 * Evaluates a policy for a subject. The policy may be synchronous or
 * asynchronous. Only the exact string `"allow"` is a permission; any other
 * value, including `"Allow"`, `undefined`, a thrown error or a rejected
 * promise, yields a deny. The one other answer is the verdict of
 * `requireFactor`, which yields a step-up when the flow can continue and a
 * deny when it cannot. An allow is recorded in the audit before it is
 * returned: if the sink throws, there is no decision.
 */
export async function evaluatePolicy(
	subject: string,
	policy: (subject: string) => unknown,
	options: EvaluatePolicyOptions = {},
): Promise<Decision> {
	const judgement = await judge(
		subject,
		policy,
		own(options, "stepUpAllowed") === true,
	);

	await report(own(options, "audit"), {
		event: AUDIT_EVENTS.policyEvaluate,
		outcome:
			judgement.kind === DECISION_KINDS.allow
				? AUDIT_OUTCOMES.success
				: AUDIT_OUTCOMES.refusal,
		reason:
			judgement.kind === DECISION_KINDS.deny
				? judgement.reason
				: judgement.kind === DECISION_KINDS.stepUp
					? AUDIT_REASONS.stepUp
					: DECISION_KINDS.allow,
		tenant: own(options, "tenant") ?? "",
		subject,
		detail: {
			...(own(options, "name") === undefined
				? {}
				: { policy: own(options, "name") ?? "" }),
			...(judgement.kind === DECISION_KINDS.stepUp
				? { factor: judgement.factor }
				: {}),
		},
	});

	if (judgement.kind === DECISION_KINDS.deny) {
		return { kind: DECISION_KINDS.deny, reason: judgement.reason };
	}

	if (judgement.kind === DECISION_KINDS.stepUp) {
		return Object.freeze({
			kind: DECISION_KINDS.stepUp,
			subject,
			factor: judgement.factor,
		});
	}

	return mintedAllowDecisions.mint({ kind: DECISION_KINDS.allow, subject });
}

export const isMintedAllow = mintedAllowDecisions.has;
