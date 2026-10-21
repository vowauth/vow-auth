/** Error codes of refused results. Each refusal of untrusted input reports exactly one of these. */
export const ERROR_CODES = {
	forbidden: "forbidden",
	invalidDelegation: "invalid-delegation",
	invalidEmail: "invalid-email",
	invalidEvent: "invalid-event",
	invalidProof: "invalid-proof",
	invalidRequest: "invalid-request",
	invalidSeal: "invalid-seal",
	invalidSession: "invalid-session",
	invalidToken: "invalid-token",
	noAllow: "no-allow",
	noProof: "no-proof",
	rateLimited: "rate-limited",
	noSubject: "no-subject",
	noSession: "no-session",
} as const;
