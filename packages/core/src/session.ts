import { isMintedAllow } from "./decision.js";
import { fail, type Result, succeed } from "./result.js";

/** An authenticated session of a subject. */
export type Session = { readonly id: string; readonly subject: string };

/**
 * Creates a session. This is the only place a session is born. The input is
 * untrusted: anything except an allow decision returned by `evaluatePolicy`
 * is rejected.
 */
export function issueSession(decision: unknown): Result<Session> {
	if (!isMintedAllow(decision)) {
		return fail("no-allow");
	}

	return succeed({ id: crypto.randomUUID(), subject: decision.subject });
}
