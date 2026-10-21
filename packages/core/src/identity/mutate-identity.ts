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
import type { SessionTokens } from "../session-tokens/session-tokens.js";
import type { IdentityStore } from "./identity-store.js";

/** What to change about a subject. */
export type IdentityChange =
	| { readonly type: "delete" }
	| { readonly type: "confirm-email"; readonly proof: unknown };

/** Everything a change touched besides the subject itself. */
export type MutationOutcome = {
	readonly affectedSubjects: readonly string[];
};

/** Options for creating `mutateIdentity`. */
export type MutateIdentityOptions = {
	readonly store: IdentityStore;
	readonly sessionTokens: Pick<SessionTokens, "revoke">;
	readonly audit?: AuditSink | undefined;
};

/** Changes a subject of a tenant, with every consequence, and reports the subjects it touched. */
export type MutateIdentity = (
	tenantId: string,
	subjectId: string,
	change: IdentityChange,
) => Promise<Result<MutationOutcome>>;

/**
 * Creates `mutateIdentity`, the only place an identity is deleted or an email
 * is confirmed against earlier claims. A change narrows access, so sessions
 * are revoked first, then the store changes, then the audit is written: a
 * failure half way leaves sessions revoked and the data intact, never a live
 * session of a removed subject. The caller decides who may ask for a change;
 * this is not an authorization check.
 *
 * - `delete` revokes every session of the subject and deletes the subject
 *   with all its identities.
 * - `confirm-email` takes a verified proof of an email that the subject owns
 *   as verified. Every other subject of the tenant that claimed the same
 *   email without verifying it is evicted: their sessions are revoked, the
 *   claims are removed, and subjects left with no identity are deleted. This
 *   ends an account takeover prepared by claiming an address nobody had
 *   proven yet.
 */
export function createMutateIdentity(
	options: MutateIdentityOptions,
): MutateIdentity {
	const { store, sessionTokens, audit } = options;
	const record = (
		outcome: typeof AUDIT_OUTCOMES.success | typeof AUDIT_OUTCOMES.refusal,
		reason: string,
		tenantId: string,
		subjectId: string,
		detail: Readonly<Record<string, string>>,
	) => {
		return report(audit, {
			event: AUDIT_EVENTS.identityMutate,
			outcome,
			reason,
			tenant: tenantId,
			subject: subjectId,
			detail,
		});
	};
	const revokeUser = (tenantId: string, subjectId: string) => {
		return sessionTokens.revoke({
			tenant: tenantId,
			scope: "user",
			id: subjectId,
		});
	};
	const refuse = async (
		reason: string,
		code: string,
		tenantId: string,
		subjectId: string,
		change: string,
	) => {
		await record(AUDIT_OUTCOMES.refusal, reason, tenantId, subjectId, {
			change,
		});

		return fail(code);
	};

	return async (tenantId, subjectId, change) => {
		if (change.type === "delete") {
			await revokeUser(tenantId, subjectId);

			if (!(await store.deleteSubject(tenantId, subjectId))) {
				return refuse(
					AUDIT_REASONS.notFound,
					ERROR_CODES.noSubject,
					tenantId,
					subjectId,
					change.type,
				);
			}

			await record(
				AUDIT_OUTCOMES.success,
				AUDIT_REASONS.deleted,
				tenantId,
				subjectId,
				{ change: change.type },
			);

			return succeed({ affectedSubjects: [subjectId] });
		}

		const { proof } = change;

		if (!isMintedProof(proof)) {
			return refuse(
				AUDIT_REASONS.noProof,
				ERROR_CODES.noProof,
				tenantId,
				subjectId,
				change.type,
			);
		}

		const { claims } = proof;

		if (!claims.emailVerified) {
			return refuse(
				AUDIT_REASONS.unverified,
				ERROR_CODES.forbidden,
				tenantId,
				subjectId,
				change.type,
			);
		}

		if (
			(await store.findSubjectByVerifiedEmail(tenantId, claims.email)) !==
			subjectId
		) {
			return refuse(
				AUDIT_REASONS.notOwner,
				ERROR_CODES.forbidden,
				tenantId,
				subjectId,
				change.type,
			);
		}

		const claimants = (
			await store.findSubjectsByUnverifiedEmail(tenantId, claims.email)
		).filter((claimant) => claimant !== subjectId);

		for (const claimant of claimants) {
			await revokeUser(tenantId, claimant);
		}

		const evicted = await store.removeUnverifiedEmailClaims(
			tenantId,
			claims.email,
			subjectId,
		);

		for (const late of evicted.filter((id) => !claimants.includes(id))) {
			await revokeUser(tenantId, late);
		}

		await record(
			AUDIT_OUTCOMES.success,
			AUDIT_REASONS.emailConfirmed,
			tenantId,
			subjectId,
			{ change: change.type, evicted: String(evicted.length) },
		);

		return succeed({ affectedSubjects: evicted });
	};
}
