/** Error codes of refused results. Each refusal of untrusted input reports exactly one of these. */
export const ERROR_CODES = {
	invalidEmail: "invalid-email",
	invalidEvent: "invalid-event",
	invalidProof: "invalid-proof",
	invalidSeal: "invalid-seal",
	invalidSession: "invalid-session",
	invalidToken: "invalid-token",
	noAllow: "no-allow",
	noProof: "no-proof",
	noSession: "no-session",
} as const;
