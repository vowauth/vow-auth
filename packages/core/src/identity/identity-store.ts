import type { IdentityClaims } from "../proof.js";
import type { CanonicalEmail } from "./canonical-email.js";

/**
 * Storage port for identities. Every method takes the tenant, so a lookup
 * without a tenant cannot be written. `createSubject` and `linkIdentity` must
 * be atomic and first-wins: they return the subject that owns the identity
 * after the call.
 */
export type IdentityStore = {
	findSubject(
		tenantId: string,
		provider: string,
		externalId: string,
	): Promise<string | undefined>;
	findSubjectByVerifiedEmail(
		tenantId: string,
		email: CanonicalEmail,
	): Promise<string | undefined>;
	createSubject(
		tenantId: string,
		identity: IdentityClaims,
	): Promise<{ readonly subjectId: string; readonly created: boolean }>;
	linkIdentity(
		tenantId: string,
		subjectId: string,
		identity: IdentityClaims,
	): Promise<string>;
};
