import type { IdentityClaims } from "../proof.js";
import type { CanonicalEmail } from "./canonical-email.js";

/** A subject as the store keeps it, apart from its identities. */
export type StoredSubject = {
	/** When the subject lost its last identity to an eviction; `undefined` while it was never evicted. */
	readonly evictedAtMilliseconds: number | undefined;
};

/**
 * Storage port for identities. Every method takes the tenant, so a lookup
 * without a tenant cannot be written, and an operation never reaches a subject
 * of another tenant. A subject is a record of its own, so the data of an
 * application can point at it; its id is unique across tenants. A subject
 * exists from the identity that created it until it is deleted, and only
 * `createSubject` makes one. `createSubject` and `linkIdentity` must be atomic
 * and first-wins: they return the subject that owns the identity after the
 * call, and a conflict never leaves a subject behind. Besides verified
 * identities the store keeps unverified claims of an email, so that confirming
 * the email can find and remove them.
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
	/**
	 * Adds the identity to a subject. Answers the owner of the identity, or
	 * `undefined` when the identity is free and the tenant has no such subject,
	 * or the subject was evicted: an identity never brings a subject back.
	 */
	linkIdentity(
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): Promise<string | undefined>;
	/** The subject of the tenant, evicted or not; `undefined` when it does not exist. */
	getSubject(
		tenant: string,
		subjectId: string,
	): Promise<StoredSubject | undefined>;
	/** The subjects of the tenant that claimed the email without verifying it. */
	findSubjectsByUnverifiedEmail(
		tenant: string,
		email: CanonicalEmail,
	): Promise<readonly string[]>;
	/**
	 * Removes every unverified claim of the email from every subject of the
	 * tenant except `keepSubjectId` and its verified owner, and returns every
	 * subject it touched. A subject left with no identity is not deleted: it is
	 * marked evicted and keeps its id, so the data of the application that
	 * points at it stays, and nobody can sign in to it again.
	 */
	removeUnverifiedEmailClaims(
		tenant: string,
		email: CanonicalEmail,
		keepSubjectId: string,
	): Promise<readonly string[]>;
	/** Deletes the subject, evicted or not, with all its identities; `false` when the tenant has no such subject. */
	deleteSubject(tenant: string, subjectId: string): Promise<boolean>;
};
