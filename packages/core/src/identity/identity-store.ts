import type { IdentityClaims } from "../proof.js";
import type { CanonicalEmail } from "./canonical-email.js";

/**
 * Storage port for identities. Every method takes the tenant, so a lookup
 * without a tenant cannot be written, and an operation never reaches a subject
 * of another tenant. `createSubject` and `linkIdentity` must be atomic and
 * first-wins: they return the subject that owns the identity after the call.
 * Besides verified identities the store keeps unverified claims of an email,
 * so that confirming the email can find and remove them.
 */
export type IdentityStore = {
	findSubject(
		tenant: string,
		provider: string,
		externalId: string,
	): Promise<string | undefined>;
	findSubjectByVerifiedEmail(
		tenant: string,
		email: CanonicalEmail,
	): Promise<string | undefined>;
	createSubject(
		tenant: string,
		identity: IdentityClaims,
	): Promise<{ readonly subjectId: string; readonly isNew: boolean }>;
	linkIdentity(
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): Promise<string>;
	/** The subjects of the tenant that claimed the email without verifying it. */
	findSubjectsByUnverifiedEmail(
		tenant: string,
		email: CanonicalEmail,
	): Promise<readonly string[]>;
	/**
	 * Removes every unverified claim of the email from every subject of the
	 * tenant except `keepSubjectId` and its verified owner, deletes the subjects
	 * left with no identity, and returns every subject it touched.
	 */
	removeUnverifiedEmailClaims(
		tenant: string,
		email: CanonicalEmail,
		keepSubjectId: string,
	): Promise<readonly string[]>;
	/** Deletes the subject with all its identities; `false` when the tenant has no such subject. */
	deleteSubject(tenant: string, subjectId: string): Promise<boolean>;
};
