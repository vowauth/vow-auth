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
import type { IdentityStore } from "./identity/identity-store.js";
import type { MutateIdentity } from "./identity/mutate-identity.js";
import {
	RESOLUTION_OUTCOMES,
	type ResolutionOutcome,
	resolveIdentity,
} from "./identity/resolve-identity.js";
import {
	type Factor,
	type Proof,
	restoreProof,
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
	/** The proof that was just made. */
	readonly proof: Proof;
	/** Every proof of this sign-in so far, in order; the last one is `proof`. */
	readonly proofs: readonly Proof[];
};

/** Options for creating the sign-in flow. */
export type SignInOptions = {
	readonly identities: IdentityStore;
	readonly sessionTokens: Pick<SessionTokens, "issue">;
	readonly mutateIdentity: MutateIdentity;
	readonly tokens: Pick<Tokens, "issue" | "consume">;
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
	readonly factor: Factor;
	readonly response: unknown;
	/** The `continuation` of a `step-up-required` refusal, when this is its second step. */
	readonly continuation?: string;
};

/** A signed in session: the bearer token and who it is for. */
export type SignedIn = {
	readonly token: string;
	readonly tenant: string;
	readonly subject: string;
	readonly device: string;
	readonly session: string;
	readonly identity: ResolutionOutcome;
	readonly email: string | undefined;
	readonly evicted: readonly string[];
};

/**
 * The refusal that is not a refusal of the person: the policy wants one more
 * factor. Nothing is signed in. Run the factor with this id and send its
 * response with the continuation, within the time the flow allows.
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
	readonly tenant: string;
	readonly device: string;
	readonly subjectId: string;
	readonly proofs: readonly Proof[];
	readonly outcome: ResolutionOutcome;
	readonly email: string | undefined;
	readonly evicted: readonly string[];
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

const parseEvicted = (
	raw: string | undefined,
): readonly string[] | undefined => {
	const parsed = raw === undefined ? undefined : safeParseJson(raw);

	return Array.isArray(parsed) &&
		parsed.every((subject) => typeof subject === "string")
		? parsed
		: undefined;
};

/**
 * Creates the sign-in flow, the only road to a session: prove with a factor,
 * resolve the identity, confirm a verified email against earlier claims, ask
 * the policy, then issue the session and its token. Every factor, present and
 * future, takes the same road, so a new factor is under the same policy,
 * audit and email confirmation without touching any other code. A factor
 * cannot create a session: the function that does is not part of the public
 * API. Every refusal reports the error of the step that refused.
 *
 * When the policy asks for one more factor with `requireFactor`, nothing is
 * signed in: the flow refuses with `step-up-required`, naming the factor and
 * handing out a one-time continuation that holds the proofs so far. The
 * second step presents the continuation with that factor's response. The
 * continuation is spent by the first try, right or wrong, so guessing the
 * second factor costs a full first step every time; the second factor must
 * identify the same subject, or the sign in is refused. The policy then sees
 * every proof and decides again. The session records which factors were
 * passed and when.
 */
export function createSignIn(options: SignInOptions): SignIn {
	const {
		identities,
		sessionTokens,
		mutateIdentity,
		tokens,
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

	const conclude = async (
		progress: Progress,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		const { tenant, device, subjectId, proofs } = progress;
		const latest = proofs[proofs.length - 1];

		if (latest === undefined) {
			return fail(ERROR_CODES.invalidProof);
		}

		const decision = await evaluatePolicy(
			subjectId,
			(subject) => policy({ subject, tenant, proof: latest, proofs }),
			{ audit, tenant, stepUpAllowed: stepUpDuration !== undefined },
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
					subject: subjectId,
					factor: decision.factor,
					proofs: JSON.stringify(proofs.map(serializeProof)),
					identity: progress.outcome,
					evicted: JSON.stringify(progress.evicted),
					...(progress.email === undefined ? {} : { email: progress.email }),
				},
				timeToLive: stepUpDuration,
			});

			return fail({
				code: ERROR_CODES.stepUpRequired,
				factor: decision.factor,
				continuation,
			});
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
			subject: subjectId,
			device,
			session: session.value.id,
			identity: progress.outcome,
			email: progress.email,
			evicted: progress.evicted,
		});
	};

	const refuseContinuation = async (
		reason: string,
		tenant: string,
		subject: string,
		factor: string,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		await report(audit, {
			event: AUDIT_EVENTS.signInContinue,
			outcome: AUDIT_OUTCOMES.refusal,
			reason,
			tenant,
			subject,
			detail: { factor },
		});

		return fail(ERROR_CODES.invalidProof);
	};

	const firstStep = async (
		request: SignInRequest,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		const { tenant, device } = request;
		const proof = await verifyProof(request.factor, request.response, {
			audit,
		});

		if (!proof.ok) {
			return fail(proof.error);
		}

		const resolution = await resolveIdentity(identities, tenant, proof.value, {
			audit,
		});

		if (!resolution.ok) {
			return fail(resolution.error);
		}

		const { subjectId, outcome } = resolution.value;

		let evicted: readonly string[] = [];

		if (proof.value.claims.emailVerified) {
			const confirmed = await mutateIdentity(tenant, subjectId, {
				type: "confirm-email",
				proof: proof.value,
			});

			if (!confirmed.ok) {
				return fail(confirmed.error);
			}

			evicted = confirmed.value.affectedSubjects;
		}

		return conclude({
			tenant,
			device,
			subjectId,
			proofs: [proof.value],
			outcome,
			email: proof.value.claims.email?.address,
			evicted,
		});
	};

	const secondStep = async (
		request: SignInRequest,
		continuation: string,
	): Promise<Result<SignedIn, SignInRefusal>> => {
		const { tenant, device, factor } = request;
		const spent = await tokens.consume(continuation, CONTINUATION_PURPOSE);

		if (!spent.ok) {
			return fail(spent.error);
		}

		const held = spent.value;
		const subject = own(held, "subject") ?? "";
		const earlier = parseProofs(own(held, "proofs"));
		const outcome = OUTCOMES.find(
			(candidate) => candidate === own(held, "identity"),
		);
		const evicted = parseEvicted(own(held, "evicted"));

		if (
			own(held, "tenant") !== tenant ||
			own(held, "device") !== device ||
			own(held, "factor") !== factor.id ||
			!isNonEmptyString(subject) ||
			earlier === undefined ||
			outcome === undefined ||
			evicted === undefined
		) {
			return refuseContinuation(
				AUDIT_REASONS.forbidden,
				tenant,
				subject,
				factor.id,
			);
		}

		const proof = await verifyProof(factor, request.response, { audit });

		if (!proof.ok) {
			return fail(proof.error);
		}

		const owner = await identities.findSubject(
			tenant,
			proof.value.claims.provider,
			proof.value.claims.externalId,
		);

		if (owner !== subject) {
			return refuseContinuation(
				AUDIT_REASONS.notOwner,
				tenant,
				subject,
				factor.id,
			);
		}

		return conclude({
			tenant,
			device,
			subjectId: subject,
			proofs: [...earlier, proof.value],
			outcome,
			email: own(held, "email"),
			evicted,
		});
	};

	return async (request) => {
		const { tenant, device } = request;
		const continuation = own(request, "continuation");

		if (
			!isStorableText(tenant) ||
			!isStorableText(device) ||
			(continuation !== undefined && !isStorableText(continuation))
		) {
			return fail(ERROR_CODES.invalidRequest);
		}

		return continuation === undefined
			? firstStep(request)
			: secondStep(request, continuation);
	};
}
