import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { isMintedProof } from "../proof.js";
import { fail, type Result, succeed } from "../result.js";
import { own } from "../shared/own.js";
import type { IdentityStore } from "./identity-store.js";

/** How an identity resolved. */
export const RESOLUTION_OUTCOMES = {
	created: "created",
	existing: "existing",
	linked: "linked",
} as const;

export type ResolutionOutcome =
	(typeof RESOLUTION_OUTCOMES)[keyof typeof RESOLUTION_OUTCOMES];

/** The subject an identity resolved to, and how. */
export type Resolution = {
	readonly subjectId: string;
	readonly outcome: ResolutionOutcome;
};

/** Options of `resolveIdentity`. */
export type ResolveIdentityOptions = {
	readonly audit?: AuditSink | undefined;
};

/**
 * Maps a proof to a subject inside one tenant. This is the only place
 * identities are linked. An identity is linked to an existing subject only
 * when the proof carries a verified email that already belongs, verified, to
 * that subject; an unverified claim never links and never takes over an
 * account. The email in a proof is already canonical, `verifyProof` made it
 * so. A link is recorded in the audit before it is made, so a failing sink
 * prevents it; a new subject is recorded right after it is created, and a
 * failing sink then leaves a subject that nothing uses.
 */
export async function resolveIdentity(
	store: IdentityStore,
	tenantId: string,
	proof: unknown,
	options: ResolveIdentityOptions = {},
): Promise<Result<Resolution>> {
	const audit = own(options, "audit");
	const record = (
		outcome: typeof AUDIT_OUTCOMES.success | typeof AUDIT_OUTCOMES.refusal,
		reason: string,
		subject: string,
		provider: string,
	) => {
		return report(audit, {
			event: AUDIT_EVENTS.identityResolve,
			outcome,
			reason,
			tenant: tenantId,
			subject,
			detail: { provider },
		});
	};

	if (!isMintedProof(proof)) {
		await record(AUDIT_OUTCOMES.refusal, AUDIT_REASONS.noProof, "", "");

		return fail(ERROR_CODES.noProof);
	}

	const identity = proof.claims;
	const existing = await store.findSubject(
		tenantId,
		identity.provider,
		identity.externalId,
	);

	if (existing !== undefined) {
		await record(
			AUDIT_OUTCOMES.success,
			RESOLUTION_OUTCOMES.existing,
			existing,
			identity.provider,
		);

		return succeed({
			subjectId: existing,
			outcome: RESOLUTION_OUTCOMES.existing,
		});
	}

	if (identity.emailVerified) {
		const owner = await store.findSubjectByVerifiedEmail(
			tenantId,
			identity.email,
		);

		if (owner !== undefined) {
			await record(
				AUDIT_OUTCOMES.success,
				RESOLUTION_OUTCOMES.linked,
				owner,
				identity.provider,
			);
			const subjectId = await store.linkIdentity(tenantId, owner, identity);

			return succeed({ subjectId, outcome: RESOLUTION_OUTCOMES.linked });
		}
	}

	const created = await store.createSubject(tenantId, identity);
	const outcome = created.created
		? RESOLUTION_OUTCOMES.created
		: RESOLUTION_OUTCOMES.existing;

	await record(
		AUDIT_OUTCOMES.success,
		outcome,
		created.subjectId,
		identity.provider,
	);

	return succeed({ subjectId: created.subjectId, outcome });
}
