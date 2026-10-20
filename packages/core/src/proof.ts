import { ERROR_CODES } from "./errors.js";
import { fail, type Result, succeed } from "./result.js";
import { isRow } from "./shared/is-row.js";
import { createMintRegistry } from "./shared/mint-registry.js";
import { own } from "./shared/own.js";

/** How a factor proves a claim. */
export type ProofStrength = "knowledge" | "possession" | "inherence";

/**
 * What a factor asserts about the identity it verified. A verified email is
 * always present: the claim cannot be verified without an address.
 */
export type IdentityClaims = {
	readonly provider: string;
	readonly externalId: string;
} & (
	| { readonly email: string; readonly emailVerified: true }
	| { readonly email?: string; readonly emailVerified: false }
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

const parseClaims = (raw: unknown): IdentityClaims | undefined => {
	if (!isRow(raw)) {
		return undefined;
	}

	for (const key of Object.keys(raw)) {
		if (!CLAIM_KEYS.includes(key)) {
			return undefined;
		}
	}

	const provider = own(raw, "provider");
	const externalId = own(raw, "externalId");
	const email = own(raw, "email");
	const emailVerified = own(raw, "emailVerified");

	if (
		!isNonEmptyString(provider) ||
		!isNonEmptyString(externalId) ||
		typeof emailVerified !== "boolean"
	) {
		return undefined;
	}

	if (emailVerified) {
		return isNonEmptyString(email)
			? Object.freeze({ provider, externalId, email, emailVerified })
			: undefined;
	}

	if (email === undefined) {
		return Object.freeze({ provider, externalId, emailVerified });
	}

	return isNonEmptyString(email)
		? Object.freeze({ provider, externalId, email, emailVerified })
		: undefined;
};

/**
 * Runs a factor and mints a proof from what it established. The claims are
 * validated against the closed claim shape and copied from own properties
 * only. Every refusal, whether the factor rejected the response, threw, or
 * returned malformed claims, reports the same `invalid-proof` error.
 */
export async function verifyProof(
	factor: Factor,
	response: unknown,
	options: VerifyProofOptions = {},
): Promise<Result<Proof>> {
	let outcome: Result<unknown>;

	try {
		outcome = await factor.verify(response);
	} catch {
		return fail(ERROR_CODES.invalidProof);
	}

	const claims = outcome.ok ? parseClaims(outcome.value) : undefined;

	if (claims === undefined) {
		return fail(ERROR_CODES.invalidProof);
	}

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
