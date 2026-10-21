import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditOutcome,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { SECRET_LENGTH } from "../shared/constants.js";
import { own } from "../shared/own.js";
import { generateSecret, hashSecret } from "../shared/secret.js";
import type { TokenStore } from "./token-store.js";

/** Options for creating the tokens primitive. */
export type TokensOptions = {
	readonly store: TokenStore;
	readonly audit?: AuditSink;
};

/** Parameters of a token to issue. */
export type IssueTokenInput = {
	readonly purpose: string;
	readonly payload?: Readonly<Record<string, string>>;
	readonly timeToLiveMilliseconds: number;
};

/** One-time secrets bound to a purpose. */
export type Tokens = {
	issue(input: IssueTokenInput): Promise<string>;
	consume(
		token: string,
		purpose: string,
	): Promise<Result<Readonly<Record<string, string>>>>;
};

/**
 * Creates the tokens primitive. A token is redeemed at most once, only for the
 * purpose it was issued for, and only before it expires. A token presented for
 * the wrong purpose is burned, not kept. Every rejection reports the same
 * `invalid-token` error, so a caller cannot learn why a token was refused; the
 * audit records the reason. Issuing and a successful redemption are recorded
 * before they take effect: if the sink throws, no token is issued, and a
 * redemption fails with the token already spent.
 */
export function createTokens(options: TokensOptions): Tokens {
	const audit = own(options, "audit");
	const record = (
		event: string,
		outcome: AuditOutcome,
		reason: string,
		purpose: string,
	) => {
		return report(audit, {
			event,
			outcome,
			reason,
			tenant: "",
			subject: "",
			detail: { purpose },
		});
	};
	const refuse = async (reason: string, purpose: string) => {
		await record(
			AUDIT_EVENTS.tokenConsume,
			AUDIT_OUTCOMES.refusal,
			reason,
			purpose,
		);

		return fail(ERROR_CODES.invalidToken);
	};

	return {
		async issue(input) {
			if (
				!Number.isFinite(input.timeToLiveMilliseconds) ||
				input.timeToLiveMilliseconds <= 0
			) {
				throw new RangeError(
					"timeToLiveMilliseconds must be a positive finite number",
				);
			}

			await record(
				AUDIT_EVENTS.tokenIssue,
				AUDIT_OUTCOMES.success,
				AUDIT_REASONS.issued,
				input.purpose,
			);

			const token = generateSecret();

			await options.store.put(await hashSecret(token), {
				purpose: input.purpose,
				payload: own(input, "payload") ?? {},
				expiresAtMilliseconds: Date.now() + input.timeToLiveMilliseconds,
			});

			return token;
		},
		async consume(token, purpose) {
			if (token.length !== SECRET_LENGTH) {
				return refuse(AUDIT_REASONS.malformed, purpose);
			}

			const stored = await options.store.take(await hashSecret(token));

			if (stored === undefined) {
				return refuse(AUDIT_REASONS.notFound, purpose);
			}

			if (stored.purpose !== purpose) {
				return refuse(AUDIT_REASONS.wrongPurpose, purpose);
			}

			if (!(Date.now() < stored.expiresAtMilliseconds)) {
				return refuse(AUDIT_REASONS.expired, purpose);
			}

			await record(
				AUDIT_EVENTS.tokenConsume,
				AUDIT_OUTCOMES.success,
				AUDIT_REASONS.consumed,
				purpose,
			);

			return succeed(stored.payload);
		},
	};
}
