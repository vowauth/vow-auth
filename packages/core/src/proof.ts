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
import { isRow } from "./shared/is-row.js";
import { createMintRegistry } from "./shared/mint-registry.js";
import { own } from "./shared/own.js";

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
	verify(response: unknown): Promise<Result<unknown>>;
};

/** Options of `verifyProof`. */
export type VerifyProofOptions = {
	readonly now?: () => number;
	readonly audit?: AuditSink | undefined;
};

const CLAIM_KEYS: readonly string[] = [
	"provider",
	"externalId",
	"email",
	"emailVerified",
];

const mintedProofs = createMintRegistry<Proof>();

const isNonEmptyString = (value: unknown): value is string => {
	return typeof value === "string" && value.length > 0;
};

const parseClaims = (raw: unknown): Result<IdentityClaims, string> => {
	if (!isRow(raw)) {
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
		!isNonEmptyString(provider) ||
		!isNonEmptyString(claimedExternalId) ||
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
 * validated against the closed claim shape and copied from own properties
 * only. Every refusal, whether the factor rejected the response, threw, or
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
		outcome = await factor.verify(response);
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
		mintedProofs.mint(
			Object.freeze({
				factor: factor.id,
				strength: factor.strength,
				verifiedAtMilliseconds: (own(options, "now") ?? Date.now)(),
				claims,
			}),
		),
	);
}

export const isMintedProof = mintedProofs.has;
