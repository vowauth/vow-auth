import type { AccountStore } from "./accounts/account-store.js";
import { applyPlan } from "./accounts/apply.js";
import {
	MEMBERSHIP_OUTCOMES,
	type MembershipOutcome,
	planSignIn,
	RESOLUTION_OUTCOMES,
	type ResolutionOutcome,
	type SignInPlan,
} from "./accounts/plan.js";
import type { Records } from "./accounts/records.js";
import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "./audit.js";
import { DECISION_KINDS, evaluatePolicy } from "./decision.js";
import { type Duration, defineDuration } from "./duration.js";
import { ERROR_CODES } from "./errors.js";
import {
	type Factor,
	type Proof,
	restoreProof,
	sameClaims,
	serializeProof,
	verifyProof,
} from "./proof.js";
import { fail, type Result, succeed } from "./result.js";
import { issueSession } from "./session.js";
import type { SessionTokens } from "./session-tokens/session-tokens.js";
import { isNonEmptyString } from "./shared/is-non-empty-string.js";
import { isStorableText } from "./shared/is-storable-text.js";
import { own } from "./shared/own.js";
import { safeParseJson } from "./shared/safe-parse-json.js";
import type { Tokens } from "./tokens/tokens.js";

const CONTINUATION_PURPOSE = "sign-in-continuation";

/** What the sign-in policy is asked about: who, where, and how they proved it. */
export type SignInPolicyInput = {
	readonly subject: string;
	readonly tenant: string;
	readonly account: string;
	/** The proof that was just made. */
	readonly proof: Proof;
	/** Every proof of this sign-in so far, in order; the last one is `proof`. */
	readonly proofs: readonly Proof[];
};

/**
 * What the registration policy is asked about: a sign in that would create
 * an account, create a membership, or bring a removed one back. Nothing is
 * written yet; the ids are the ones the writes will use.
 */
export type RegistrationPolicyInput = {
	readonly tenant: string;
	readonly account: string;
	readonly subject: string;
	readonly proof: Proof;
	readonly proofs: readonly Proof[];
	readonly newAccount: boolean;
	readonly newMembership:
		| typeof MEMBERSHIP_OUTCOMES.created
		| typeof MEMBERSHIP_OUTCOMES.rejoined
		| undefined;
	/**
	 * Another account owns the email of the identity this sign in would
	 * create. Refuse to tell the person to sign in the way they did before.
	 */
	readonly emailOwnedByAnotherAccount: boolean;
};

/** Options for creating the sign-in flow. */
export type SignInOptions = {
	/** The factors of the engine by id; a sign in names one of them. */
	readonly factors: ReadonlyMap<string, Factor>;
	readonly accounts: AccountStore;
	readonly records: Records;
	/** The providers whose verified emails link accounts and count as verified. */
	readonly trustedProviders: readonly string[];
	readonly sessionTokens: Pick<SessionTokens, "issue" | "revoke">;
	readonly tokens: Pick<Tokens, "issue" | "consume">;
	/** Answers `"allow"` to let a sign in create an account or a membership, or bring one back; anything else refuses. */
	readonly registration: (input: RegistrationPolicyInput) => unknown;
	/**
	 * Answers `"allow"` to let the subject in, or `requireFactor(id)` to ask for
	 * one more factor; anything else keeps them out. Sees the proofs, so it can
	 * demand a stronger or fresher one.
	 */
	readonly policy: (input: SignInPolicyInput) => unknown;
	readonly sessionTimeToLiveMilliseconds: number;
	/**
	 * How long a person has to pass the second factor after the first. Without
	 * it a policy cannot ask for another factor, and a step-up verdict is a deny.
	 */
	readonly stepUpTimeToLiveMilliseconds?: number | undefined;
	readonly audit?: AuditSink | undefined;
};

/** One attempt to sign in, or the second step of one. */
export type SignInRequest = {
	readonly tenant: string;
	readonly device: string;
	/** The id of a factor the engine was created with; a sign in cannot bring its own. */
	readonly factor: string;
	readonly response: unknown;
	/** The `continuation` of a `step-up-required` refusal, when this is its second step. */
	readonly continuation?: string;
};

/** A signed in session: the bearer token and who it is for. */
export type SignedIn = {
	readonly token: string;
	readonly tenant: string;
	readonly account: string;
	readonly subject: string;
	readonly device: string;
	readonly session: string;
	readonly identity: ResolutionOutcome;
	readonly membership: MembershipOutcome;
	readonly email: string | undefined;
	/** The accounts whose unverified claims of the proven email were evicted. */
	readonly evicted: readonly string[];
};

/**
 * The refusal that is not a refusal of the person: the policy wants one more
 * factor. Nothing is signed in and nothing is written. Run the factor with
 * this id and send its response with the continuation, within the time the
 * flow allows.
 */
export type StepUpRequired = {
	readonly code: typeof ERROR_CODES.stepUpRequired;
	readonly factor: string;
	readonly continuation: string;
};

/** Why a sign in did not give a session: an error code, or a request for one more factor. */
export type SignInRefusal = string | StepUpRequired;

/** Signs a person in with any factor. */
export type SignIn = (
	request: SignInRequest,
) => Promise<Result<SignedIn, SignInRefusal>>;

type Progress = {
	readonly device: string;
	readonly plan: SignInPlan;
	readonly proofs: readonly Proof[];
};

const OUTCOMES: readonly ResolutionOutcome[] =
	Object.values(RESOLUTION_OUTCOMES);

const parseProofs = (raw: string | undefined): readonly Proof[] | undefined => {
	const texts = raw === undefined ? undefined : safeParseJson(raw);

	if (!Array.isArray(texts) || texts.length === 0) {
		return undefined;
	}

	const proofs: Proof[] = [];

	for (const text of texts) {
		const restored = typeof text === "string" ? restoreProof(text) : undefined;

		if (restored === undefined || !restored.ok) {
			return undefined;
		}

		proofs.push(restored.value);
	}

	return proofs;
};

/**
 * Creates the sign-in flow, the only road to a session: prove with a factor
 * of the engine, named by its id; plan who this is and what letting them in
 * would change, reading only; ask the registration policy when the plan
 * creates an account or a membership or brings one back; ask the sign-in
 * policy; and only when both allow, write the plan, evict the unverified
 * claims of a proven email, and issue the session and its token. A refused
 * or unfinished sign in writes nothing. Every factor, present and future,
 * takes the same road, so a new factor is under the same policies, audit and
 * eviction without touching any other code. A factor cannot create a session:
 * the function that does is not part of the public API. Every refusal reports
 * the error of the step that refused.
 *
 * When the policy asks for one more factor with `requireFactor`, the flow
 * refuses with `step-up-required`, naming the factor and handing out a
 * one-time continuation that holds the proofs so far. The second step
 * presents the continuation with that factor's response. The continuation is
 * spent by the first try, right or wrong, so guessing the second factor costs
 * a full first step every time. The second factor must repeat the claims of
 * an earlier proof or prove an identity of the same account; the plan is made
 * again from the first proof, since the records may have changed in between,
 * and both policies decide again with every proof. The session records which
 * factors were passed and when.
 */
export function createSignIn(options: SignInOptions): SignIn {
	const {
		factors,
		accounts,
		records,
		trustedProviders,
		sessionTokens,
		tokens,
		registration,
		policy,
		sessionTimeToLiveMilliseconds,
		audit,
	} = options;
	const sessionTimeToLive = defineDuration(sessionTimeToLiveMilliseconds);
	const stepUpMilliseconds = own(options, "stepUpTimeToLiveMilliseconds");
	const stepUpTimeToLive: Result<Duration> | undefined =
		stepUpMilliseconds === undefined
			? undefined
			: defineDuration(stepUpMilliseconds);

	if (!sessionTimeToLive.ok) {
		throw new RangeError(
			"sessionTimeToLiveMilliseconds must be a positive finite number",
		);
	}

	if (stepUpTimeToLive !== undefined && !stepUpTimeToLive.ok) {
		throw new RangeError(
			"stepUpTimeToLiveMilliseconds must be a positive finite number",
		);
	}

	const stepUpDuration = stepUpTimeToLive?.ok
		? stepUpTimeToLive.value
		: undefined;

	const plan = (tenant: string, proof: Proof) =>
		planSignIn(
			{ store: accounts, records, trustedProviders, audit },
			tenant,
			proof,
		);

	const conclude = async (
		progress: Progress,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		const { device, plan: current, proofs } = progress;
		const { tenant, accountId, subjectId } = current;
		const latest = proofs[proofs.length - 1];
		const first = proofs[0];

		if (latest === undefined || first === undefined) {
			return fail(ERROR_CODES.invalidProof);
		}

		const newAccount = current.identity === RESOLUTION_OUTCOMES.created;
		const newMembership =
			current.membership === MEMBERSHIP_OUTCOMES.existing
				? undefined
				: current.membership;

		if (newAccount || newMembership !== undefined) {
			const registered = await evaluatePolicy(
				subjectId,
				(subject) =>
					registration({
						tenant,
						account: accountId,
						subject,
						proof: latest,
						proofs,
						newAccount,
						newMembership,
						emailOwnedByAnotherAccount: current.emailOwnedByAnotherAccount,
					}),
				{ audit, tenant, stepUpAllowed: false, name: "registration" },
			);

			if (registered.kind !== DECISION_KINDS.allow) {
				return fail(ERROR_CODES.noAllow);
			}
		}

		const decision = await evaluatePolicy(
			subjectId,
			(subject) =>
				policy({ subject, tenant, account: accountId, proof: latest, proofs }),
			{
				audit,
				tenant,
				stepUpAllowed: stepUpDuration !== undefined,
				name: "sign-in",
			},
		);

		if (decision.kind === DECISION_KINDS.stepUp) {
			if (
				stepUpDuration === undefined ||
				proofs.some((proof) => proof.factor === decision.factor)
			) {
				return fail(ERROR_CODES.noAllow);
			}

			const continuation = await tokens.issue({
				purpose: CONTINUATION_PURPOSE,
				payload: {
					tenant,
					device,
					account: accountId,
					identity: current.identity,
					factor: decision.factor,
					proofs: JSON.stringify(proofs.map(serializeProof)),
				},
				timeToLive: stepUpDuration,
			});

			return fail({
				code: ERROR_CODES.stepUpRequired,
				factor: decision.factor,
				continuation,
			});
		}

		if (decision.kind !== DECISION_KINDS.allow) {
			return fail(ERROR_CODES.noAllow);
		}

		const applied = await applyPlan(
			{ store: accounts, sessionTokens, trustedProviders, audit },
			current,
		);

		if (!applied.ok) {
			return fail(applied.error);
		}

		const session = issueSession(decision);

		if (!session.ok) {
			return fail(session.error);
		}

		const token = await sessionTokens.issue(session.value, {
			tenant,
			device,
			timeToLive: sessionTimeToLive.value,
			methods: proofs.map((proof) => proof.factor),
		});

		if (!token.ok) {
			return fail(token.error);
		}

		return succeed({
			token: token.value,
			tenant,
			account: accountId,
			subject: subjectId,
			device,
			session: session.value.id,
			identity: current.identity,
			membership: current.membership,
			email: first.claims.email?.address,
			evicted: applied.value,
		});
	};

	const refuseContinuation = async (
		reason: string,
		tenant: string,
		factor: string,
		account: string,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		await report(audit, {
			event: AUDIT_EVENTS.signInContinue,
			outcome: AUDIT_OUTCOMES.refusal,
			reason,
			tenant,
			subject: "",
			detail: { factor, account },
		});

		return fail(ERROR_CODES.invalidProof);
	};

	const firstStep = async (
		request: SignInRequest,
		factor: Factor,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		const { tenant, device } = request;
		const proof = await verifyProof(factor, request.response, {
			audit,
			context: { tenant, proofs: [] },
		});

		if (!proof.ok) {
			return fail(proof.error);
		}

		const planned = await plan(tenant, proof.value);

		if (!planned.ok) {
			return fail(planned.error);
		}

		return conclude({ device, plan: planned.value, proofs: [proof.value] });
	};

	const secondStep = async (
		request: SignInRequest,
		factor: Factor,
		continuation: string,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		const { tenant, device } = request;
		const spent = await tokens.consume(continuation, CONTINUATION_PURPOSE);

		if (!spent.ok) {
			return fail(spent.error);
		}

		const held = spent.value;
		const account = own(held, "account") ?? "";
		const earlier = parseProofs(own(held, "proofs"));
		const outcome = OUTCOMES.find(
			(candidate) => candidate === own(held, "identity"),
		);
		const first = earlier?.[0];

		if (
			own(held, "tenant") !== tenant ||
			own(held, "device") !== device ||
			own(held, "factor") !== factor.id ||
			!isNonEmptyString(account) ||
			earlier === undefined ||
			first === undefined ||
			outcome === undefined
		) {
			return refuseContinuation(
				AUDIT_REASONS.forbidden,
				tenant,
				factor.id,
				account,
			);
		}

		const proof = await verifyProof(factor, request.response, {
			audit,
			context: { tenant, account, proofs: earlier },
		});

		if (!proof.ok) {
			return fail(proof.error);
		}

		const claims = proof.value.claims;

		if (!earlier.some((previous) => sameClaims(previous.claims, claims))) {
			const owned = await accounts.findIdentity(
				claims.provider,
				claims.externalId,
			);

			if (
				owned === undefined ||
				owned.accountId !== account ||
				(await records.checkIdentity(owned)) === "invalid"
			) {
				return refuseContinuation(
					AUDIT_REASONS.notOwner,
					tenant,
					factor.id,
					account,
				);
			}
		}

		const planned = await plan(tenant, first);

		if (!planned.ok) {
			return fail(planned.error);
		}

		const sameAccount =
			outcome === RESOLUTION_OUTCOMES.created
				? planned.value.identity === RESOLUTION_OUTCOMES.created
				: planned.value.accountId === account;

		if (!sameAccount) {
			return refuseContinuation(
				AUDIT_REASONS.conflict,
				tenant,
				factor.id,
				account,
			);
		}

		return conclude({
			device,
			plan: planned.value,
			proofs: [...earlier, proof.value],
		});
	};

	return async (request) => {
		const { tenant, device } = request;
		const continuation = own(request, "continuation");
		const factor =
			typeof request.factor === "string"
				? factors.get(request.factor)
				: undefined;

		if (
			!isStorableText(tenant) ||
			!isStorableText(device) ||
			(continuation !== undefined && !isStorableText(continuation)) ||
			factor === undefined
		) {
			return fail(ERROR_CODES.invalidRequest);
		}

		return continuation === undefined
			? firstStep(request, factor)
			: secondStep(request, factor, continuation);
	};
}
