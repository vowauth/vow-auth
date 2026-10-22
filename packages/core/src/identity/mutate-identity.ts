import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditOutcome,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { isMintedProof } from "../proof.js";
import { fail, type Result, succeed } from "../result.js";
import {
	REVOCATION_SCOPES,
	type SessionTokens,
} from "../session-tokens/session-tokens.js";
import type { ValueOf } from "../shared/value-of.js";
import type { IdentityStore } from "./identity-store.js";

/** The kinds of change `mutateIdentity` makes. */
export const IDENTITY_CHANGE_TYPES = {
	confirmEmail: "confirm-email",
	delete: "delete",
} as const;

type IdentityChangeType = ValueOf<typeof IDENTITY_CHANGE_TYPES>;

/** What to change about a subject. */
export type IdentityChange =
	| { readonly type: typeof IDENTITY_CHANGE_TYPES.delete }
	| {
			readonly type: typeof IDENTITY_CHANGE_TYPES.confirmEmail;
			readonly proof: unknown;
	  };

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
	tenant: string,
	subject: string,
	change: IdentityChange,
) => Promise<Result<MutationOutcome>>;

type MutationDetail = {
	readonly change: IdentityChangeType;
	readonly evicted?: string;
};

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
		outcome: AuditOutcome,
		reason: string,
		tenant: string,
		subject: string,
		detail: MutationDetail,
	) => {
		return report(audit, {
			event: AUDIT_EVENTS.identityMutate,
			outcome,
			reason,
			tenant,
			subject,
			detail,
		});
	};

	const revokeUser = (tenant: string, subject: string) => {
		return sessionTokens.revoke({
			tenant,
			scope: REVOCATION_SCOPES.user,
			id: subject,
		});
	};

	const refuse = async (
		reason: string,
		code: string,
		tenant: string,
		subject: string,
		change: IdentityChangeType,
	) => {
		await record(AUDIT_OUTCOMES.refusal, reason, tenant, subject, { change });

		return fail(code);
	};

	return async (tenant, subject, change) => {
		if (change.type === IDENTITY_CHANGE_TYPES.delete) {
			await revokeUser(tenant, subject);

			const deleted = await store.deleteSubject(tenant, subject);

			if (!deleted) {
				return refuse(
					AUDIT_REASONS.notFound,
					ERROR_CODES.noSubject,
					tenant,
					subject,
					change.type,
				);
			}

			await record(
				AUDIT_OUTCOMES.success,
				AUDIT_REASONS.deleted,
				tenant,
				subject,
				{ change: change.type },
			);

			return succeed({ affectedSubjects: [subject] });
		}

		const { proof } = change;

		if (!isMintedProof(proof)) {
			return refuse(
				AUDIT_REASONS.noProof,
				ERROR_CODES.noProof,
				tenant,
				subject,
				change.type,
			);
		}

		const { claims } = proof;

		if (!claims.emailVerified) {
			return refuse(
				AUDIT_REASONS.unverified,
				ERROR_CODES.forbidden,
				tenant,
				subject,
				change.type,
			);
		}

		const owner = await store.findSubjectByVerifiedEmail(tenant, claims.email);

		if (owner !== subject) {
			return refuse(
				AUDIT_REASONS.notOwner,
				ERROR_CODES.forbidden,
				tenant,
				subject,
				change.type,
			);
		}

		const claimants = await store.findSubjectsByUnverifiedEmail(
			tenant,
			claims.email,
		);
		const earlierClaimants = claimants.filter(
			(claimant) => claimant !== subject,
		);

		for (const claimant of earlierClaimants) {
			await revokeUser(tenant, claimant);
		}

		const evicted = await store.removeUnverifiedEmailClaims(
			tenant,
			claims.email,
			subject,
		);
		const lateClaimants = evicted.filter(
			(claimant) => !earlierClaimants.includes(claimant),
		);

		for (const claimant of lateClaimants) {
			await revokeUser(tenant, claimant);
		}

		await record(
			AUDIT_OUTCOMES.success,
			AUDIT_REASONS.emailConfirmed,
			tenant,
			subject,
			{ change: change.type, evicted: String(evicted.length) },
		);

		return succeed({ affectedSubjects: evicted });
	};
}
