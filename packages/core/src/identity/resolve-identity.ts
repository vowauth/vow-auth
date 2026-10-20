import { ERROR_CODES } from "../errors.js";
import { type IdentityClaims, isMintedProof } from "../proof.js";
import { fail, type Result, succeed } from "../result.js";
import { canonicalizeEmail } from "./canonical-email.js";
import type { IdentityStore } from "./identity-store.js";

/** The subject an identity resolved to, and how. */
export type Resolution = {
	readonly subjectId: string;
	readonly outcome: "existing" | "linked" | "created";
};

const EMAIL_PROVIDER = "email";

/**
 * Maps a proof to a subject inside one tenant. This is the only place emails
 * are canonicalized and the only place identities are linked. An identity is
 * linked to an existing subject only when the proof carries a verified email
 * that already belongs, verified, to that subject; an unverified claim never
 * links and never takes over an account. Provider `email` is identified by its
 * canonical email address.
 */
export async function resolveIdentity(
	store: IdentityStore,
	tenantId: string,
	proof: unknown,
): Promise<Result<Resolution>> {
	if (!isMintedProof(proof)) {
		return fail(ERROR_CODES.noProof);
	}

	let email: string | undefined;

	if (proof.claims.email !== undefined) {
		email = canonicalizeEmail(proof.claims.email);

		if (email === undefined) {
			return fail(ERROR_CODES.invalidEmail);
		}
	}

	const externalId =
		proof.claims.provider === EMAIL_PROVIDER && email !== undefined
			? email
			: proof.claims.externalId;
	const identity: IdentityClaims =
		email === undefined
			? {
					provider: proof.claims.provider,
					externalId,
					emailVerified: false,
				}
			: {
					provider: proof.claims.provider,
					externalId,
					email,
					emailVerified: proof.claims.emailVerified,
				};

	const existing = await store.findSubject(
		tenantId,
		identity.provider,
		identity.externalId,
	);

	if (existing !== undefined) {
		return succeed({ subjectId: existing, outcome: "existing" });
	}

	if (identity.emailVerified) {
		const owner = await store.findSubjectByVerifiedEmail(
			tenantId,
			identity.email,
		);

		if (owner !== undefined) {
			const subjectId = await store.linkIdentity(tenantId, owner, identity);

			return succeed({ subjectId, outcome: "linked" });
		}
	}

	const created = await store.createSubject(tenantId, identity);

	return succeed({
		subjectId: created.subjectId,
		outcome: created.created ? "created" : "existing",
	});
}
