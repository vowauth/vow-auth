import type { Auth } from "@vow-auth/core";

/** The routes of the service. Every one is a POST that takes and answers JSON. */
export const SERVICE_ROUTES = {
	deleteIdentity: "/v1/identities/delete",
	meterConsume: "/v1/meter/consume",
	meterObserve: "/v1/meter/observe",
	revokeSession: "/v1/sessions/revoke",
	signIn: "/v1/sign-in",
	verifySession: "/v1/sessions/verify",
} as const;

/**
 * The part of `Auth` that the service exposes, and that the client gives back
 * with the same shapes, so that code written against it works in process and
 * over the network. `mutateIdentity` over the network only deletes: confirming
 * an email needs a proof that the core issued and that cannot travel.
 */
export type ServiceSurface = Pick<
	Auth,
	"signIn" | "sessions" | "meter" | "mutateIdentity"
>;
