import type { AuditSink } from "./audit.js";
import { evaluatePolicy } from "./decision.js";
import { defineDuration } from "./duration.js";
import { ERROR_CODES } from "./errors.js";
import type { IdentityStore } from "./identity/identity-store.js";
import type { MutateIdentity } from "./identity/mutate-identity.js";
import {
	type ResolutionOutcome,
	resolveIdentity,
} from "./identity/resolve-identity.js";
import { type Factor, type Proof, verifyProof } from "./proof.js";
import { fail, type Result, succeed } from "./result.js";
import { issueSession } from "./session.js";
import type { SessionTokens } from "./session-tokens/session-tokens.js";
import { isNonEmptyString } from "./shared/is-non-empty-string.js";

/** What the sign-in policy is asked about: who, where, and how they proved it. */
export type SignInPolicyInput = {
	readonly subject: string;
	readonly tenant: string;
	readonly proof: Proof;
};

/** Options for creating the sign-in flow. */
export type SignInOptions = {
	readonly identities: IdentityStore;
	readonly sessionTokens: Pick<SessionTokens, "issue">;
	readonly mutateIdentity: MutateIdentity;
	/** Answers `"allow"` to let the subject in; anything else keeps them out. Sees the proof, so it can demand a stronger or fresher one. */
	readonly policy: (input: SignInPolicyInput) => unknown;
	readonly sessionTimeToLiveMilliseconds: number;
	readonly audit?: AuditSink | undefined;
};

/** One attempt to sign in. */
export type SignInRequest = {
	readonly tenant: string;
	readonly device: string;
	readonly factor: Factor;
	readonly response: unknown;
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

/** Signs a person in with any factor. */
export type SignIn = (request: SignInRequest) => Promise<Result<SignedIn>>;

/**
 * Creates the sign-in flow, the only road to a session: prove with a factor,
 * resolve the identity, confirm a verified email against earlier claims, ask
 * the policy, then issue the session and its token. Every factor, present and
 * future, takes the same road, so a new factor is under the same policy,
 * audit and email confirmation without touching any other code. A factor
 * cannot create a session: the function that does is not part of the public
 * API. Every refusal reports the error of the step that refused.
 */
export function createSignIn(options: SignInOptions): SignIn {
	const {
		identities,
		sessionTokens,
		mutateIdentity,
		policy,
		sessionTimeToLiveMilliseconds,
		audit,
	} = options;
	const sessionTimeToLive = defineDuration(sessionTimeToLiveMilliseconds);

	if (!sessionTimeToLive.ok) {
		throw new RangeError(
			"sessionTimeToLiveMilliseconds must be a positive finite number",
		);
	}

	return async (request) => {
		const { tenant, device } = request;

		if (!isNonEmptyString(tenant) || !isNonEmptyString(device)) {
			return fail(ERROR_CODES.invalidRequest);
		}

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

		const decision = await evaluatePolicy(
			subjectId,
			(subject) => policy({ subject, tenant, proof: proof.value }),
			{ audit, tenant },
		);

		const session = issueSession(decision);

		if (!session.ok) {
			return fail(session.error);
		}

		const token = await sessionTokens.issue(session.value, {
			tenant,
			device,
			timeToLive: sessionTimeToLive.value,
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
			identity: outcome,
			email: proof.value.claims.email?.address,
			evicted,
		});
	};
}
