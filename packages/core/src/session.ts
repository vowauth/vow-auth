import { isMintedAllow } from "./decision.js";
import { fail, type Result, succeed } from "./result.js";
import { generateSecret } from "./shared/secret.js";

/**
 * An authenticated session of a subject. The id names the session for
 * revocation; the bearer credential is the token from `SessionTokens.issue`.
 */
export type Session = { readonly id: string; readonly subject: string };

const bornSessions = new WeakSet<Session>();

/**
 * Creates a session. This is the only place a session is born. The input is
 * untrusted: anything except an allow decision returned by `evaluatePolicy`
 * is rejected.
 */
export function issueSession(decision: unknown): Result<Session> {
	if (!isMintedAllow(decision)) {
		return fail("no-allow");
	}

	const session: Session = Object.freeze({
		id: generateSecret(),
		subject: decision.subject,
	});
	bornSessions.add(session);

	return succeed(session);
}

export const isBornSession = (value: unknown): value is Session => {
	return bornSessions.has(value as Session);
};
