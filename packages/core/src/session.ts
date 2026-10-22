import { isMintedAllow } from "./decision.js";
import { ERROR_CODES } from "./errors.js";
import { fail, type Result, succeed } from "./result.js";
import { createMintRegistry } from "./shared/mint-registry.js";
import { generateSecret } from "./shared/secret.js";

/**
 * An authenticated session of a subject. The id names the session for
 * revocation; the bearer credential is the token from `SessionTokens.issue`.
 */
export type Session = { readonly id: string; readonly subject: string };

const bornSessions = createMintRegistry<Session>();

/**
 * Creates a session. This is the only place a session is born. The input is
 * untrusted: anything except an allow decision returned by `evaluatePolicy`
 * is rejected.
 */
export function issueSession(decision: unknown): Result<Session> {
	if (!isMintedAllow(decision)) {
		return fail(ERROR_CODES.noAllow);
	}

	return succeed(
		bornSessions.mint({ id: generateSecret(), subject: decision.subject }),
	);
}

export const isBornSession = bornSessions.has;
