import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "./audit.js";
import { ERROR_CODES } from "./errors.js";
import {
	type CanonicalEmail,
	canonicalizeEmail,
} from "./identity/canonical-email.js";
import { fail, type Result, succeed } from "./result.js";
import { isNonEmptyString } from "./shared/is-non-empty-string.js";
import { isPlainObject } from "./shared/is-plain-object.js";
import { isStorableText } from "./shared/is-storable-text.js";
import { createMintRegistry } from "./shared/mint-registry.js";
import { own } from "./shared/own.js";
import { safeParseJson } from "./shared/safe-parse-json.js";

/** The provider name of identities that are identified by their email address alone. */
export const EMAIL_PROVIDER = "email";

/** How a factor proves a claim. */
export type ProofStrength = "knowledge" | "possession" | "inherence";

/**
 * What a factor asserts about the identity it verified. A verified email is
 * always present: the claim cannot be verified without an address. The email
 * is canonical, and for the provider `email` it is also the external id.
 */
export type IdentityClaims = {
	readonly provider: string;
	readonly externalId: string;
} & (
	| { readonly email: CanonicalEmail; readonly emailVerified: true }
	| { readonly email?: CanonicalEmail; readonly emailVerified: false }
);

/**
 * Evidence that a factor verified a claim. A proof proves; it never creates a
 * session or changes an identity. Only `verifyProof` mints one.
 */
export type Proof = {
	readonly factor: string;
	readonly strength: ProofStrength;
	readonly verifiedAtMilliseconds: number;
	readonly claims: IdentityClaims;
};

/**
 * A way to prove a claim, supplied by a plugin. `verify` checks the response
 * and returns the claims it established. Anything it returns is untrusted
 * until `verifyProof` has validated it.
 */
export type Factor = {
	readonly id: string;
	readonly strength: ProofStrength;
	verify(response: unknown, context: FactorContext): Promise<Result<unknown>>;
};

/**
 * What the sign in knows when it asks a factor to verify. In the first step
 * there is no subject and no proof yet. In the second step of a step-up the
 * subject is the one the first factor identified and the proofs are the ones
 * it has passed, so a second factor can look up what it holds for that
 * subject and return the claims of an earlier proof, instead of trusting the
 * client to say who it is.
 */
export type FactorContext = {
	readonly tenant: string;
	readonly subject?: string;
	readonly proofs: readonly Proof[];
};

/** Options of `verifyProof`. */
export type VerifyProofOptions = {
	readonly context?: FactorContext;
	readonly now?: () => number;
	readonly audit?: AuditSink | undefined;
};

const CLAIM_KEYS: readonly string[] = [
	"provider",
	"externalId",
	"email",
	"emailVerified",
];

const NO_CONTEXT: FactorContext = Object.freeze({ tenant: "", proofs: [] });

const mintedProofs = createMintRegistry<Proof>();

const parseClaims = (raw: unknown): Result<IdentityClaims, string> => {
	if (!isPlainObject(raw)) {
		return fail(AUDIT_REASONS.invalidClaims);
	}

	for (const key of Object.keys(raw)) {
		if (!CLAIM_KEYS.includes(key)) {
			return fail(AUDIT_REASONS.invalidClaims);
		}
	}

	const provider = own(raw, "provider");
	const claimedExternalId = own(raw, "externalId");
	const claimedEmail = own(raw, "email");
	const emailVerified = own(raw, "emailVerified");

	if (
		!isStorableText(provider) ||
		!isNonEmptyString(claimedExternalId) ||
		(provider !== EMAIL_PROVIDER && !isStorableText(claimedExternalId)) ||
		typeof emailVerified !== "boolean" ||
		(claimedEmail !== undefined && !isNonEmptyString(claimedEmail)) ||
		(provider === EMAIL_PROVIDER && claimedEmail === undefined)
	) {
		return fail(AUDIT_REASONS.invalidClaims);
	}

	if (claimedEmail === undefined) {
		return emailVerified
			? fail(AUDIT_REASONS.invalidClaims)
			: succeed(
					Object.freeze({
						provider,
						externalId: claimedExternalId,
						emailVerified,
					}),
				);
	}

	const email = canonicalizeEmail(claimedEmail);

	if (email === undefined) {
		return fail(AUDIT_REASONS.invalidEmail);
	}

	const externalId =
		provider === EMAIL_PROVIDER ? email.address : claimedExternalId;

	return succeed(Object.freeze({ provider, externalId, email, emailVerified }));
};

/**
 * Runs a factor and mints a proof from what it established. The claims are
 * validated against the closed claim shape, so a claim the core does not
 * understand is refused instead of ignored, and copied from own properties
 * only; the copy is frozen, because a proof must not change after it was
 * minted. Every refusal, whether the factor rejected the response, threw, or
 * returned malformed claims, reports the same `invalid-proof` error; the
 * audit tells them apart. A verified proof is recorded before it is minted:
 * if the sink throws, there is no proof.
 */
export async function verifyProof(
	factor: Factor,
	response: unknown,
	options: VerifyProofOptions = {},
): Promise<Result<Proof>> {
	const audit = own(options, "audit");

	const refuse = async (reason: string): Promise<Result<Proof>> => {
		await report(audit, {
			event: AUDIT_EVENTS.proofVerify,
			outcome: AUDIT_OUTCOMES.refusal,
			reason,
			tenant: "",
			subject: "",
			detail: { factor: factor.id },
		});

		return fail(ERROR_CODES.invalidProof);
	};

	let outcome: Result<unknown>;

	try {
		outcome = await factor.verify(
			response,
			own(options, "context") ?? NO_CONTEXT,
		);
	} catch {
		return refuse(AUDIT_REASONS.factorError);
	}

	if (!outcome.ok) {
		return refuse(AUDIT_REASONS.factorRejected);
	}

	const parsed = parseClaims(outcome.value);

	if (!parsed.ok) {
		return refuse(parsed.error);
	}

	const claims = parsed.value;

	await report(audit, {
		event: AUDIT_EVENTS.proofVerify,
		outcome: AUDIT_OUTCOMES.success,
		reason: AUDIT_REASONS.verified,
		tenant: "",
		subject: "",
		detail: {
			factor: factor.id,
			provider: claims.provider,
			emailVerified: String(claims.emailVerified),
		},
	});

	return succeed(
		mintedProofs.mint({
			factor: factor.id,
			strength: factor.strength,
			verifiedAtMilliseconds: (own(options, "now") ?? Date.now)(),
			claims,
		}),
	);
}

export const isMintedProof = mintedProofs.has;

const PROOF_STRENGTHS = ["knowledge", "possession", "inherence"] as const;

/**
 * Writes a proof as text, so it can wait in a store between two steps of a
 * sign-in. Only `restoreProof` turns the text back into a proof.
 */
export const serializeProof = (proof: Proof): string => {
	return JSON.stringify({
		factor: proof.factor,
		strength: proof.strength,
		verifiedAtMilliseconds: proof.verifiedAtMilliseconds,
		claims: {
			provider: proof.claims.provider,
			externalId: proof.claims.externalId,
			email: proof.claims.email?.address,
			emailVerified: proof.claims.emailVerified,
		},
	});
};

/**
 * Mints a proof again from text that `serializeProof` wrote and a store kept.
 * The claims go through the same closed-shape check as a factor's, so a
 * damaged record is refused with `invalid-proof`, never trusted.
 */
export const restoreProof = (text: string): Result<Proof> => {
	const stored = safeParseJson(text);

	if (!isPlainObject(stored)) {
		return fail(ERROR_CODES.invalidProof);
	}

	const factor = own(stored, "factor");
	const strength = PROOF_STRENGTHS.find(
		(candidate) => candidate === own(stored, "strength"),
	);
	const verifiedAtMilliseconds = own(stored, "verifiedAtMilliseconds");
	const claims = parseClaims(own(stored, "claims"));

	if (
		!isNonEmptyString(factor) ||
		strength === undefined ||
		typeof verifiedAtMilliseconds !== "number" ||
		!Number.isFinite(verifiedAtMilliseconds) ||
		!claims.ok
	) {
		return fail(ERROR_CODES.invalidProof);
	}

	return succeed(
		mintedProofs.mint({
			factor,
			strength,
			verifiedAtMilliseconds,
			claims: claims.value,
		}),
	);
};
