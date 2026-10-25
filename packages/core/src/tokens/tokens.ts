import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditOutcome,
	type AuditSink,
	report,
} from "../audit.js";
import { type Duration, isDuration } from "../duration.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import type { SealDomain } from "../sealer.js";
import { SECRET_LENGTH } from "../shared/constants.js";
import { own } from "../shared/own.js";
import { generateSecret, hashSecret } from "../shared/secret.js";
import { isStoreFullError } from "../store-full.js";
import type { TokenStore } from "./token-store.js";

/** Options for creating the tokens primitive. */
export type TokensOptions = {
	readonly store: TokenStore;
	/**
	 * Whose tokens these are. The domain is stored with the purpose, so a
	 * token of one domain is never redeemed in another: a factor cannot issue
	 * a token that the core or another factor takes for its own. `core` when
	 * left out.
	 */
	readonly domain?: SealDomain | undefined;
	readonly audit?: AuditSink | undefined;
};

/** Parameters of a token to issue. */
export type IssueTokenInput = {
	readonly purpose: string;
	readonly payload?: Readonly<Record<string, string>>;
	readonly timeToLive: Duration;
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
 * audit records the reason. The secret of a new token is handed out only
 * after the audit has recorded it, so if the sink throws nobody holds a
 * token; a store with no room refuses with an error that the audit records as
 * `capacity`. A successful redemption is recorded before its payload is
 * handed out: if the sink throws, the redemption fails with the token already
 * spent.
 */
export function createTokens(options: TokensOptions): Tokens {
	const audit = own(options, "audit");
	const domain = own(options, "domain") ?? "core";
	const stored = (purpose: string): string => JSON.stringify([domain, purpose]);

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
			if (!isDuration(input.timeToLive)) {
				throw new TypeError("timeToLive must come from defineDuration");
			}

			const token = generateSecret();

			try {
				await options.store.put(await hashSecret(token), {
					purpose: stored(input.purpose),
					payload: own(input, "payload") ?? {},
					expiresAtMilliseconds: Date.now() + input.timeToLive.milliseconds,
				});
			} catch (error) {
				if (isStoreFullError(error)) {
					await record(
						AUDIT_EVENTS.tokenIssue,
						AUDIT_OUTCOMES.refusal,
						AUDIT_REASONS.capacity,
						input.purpose,
					);
				}

				throw error;
			}

			await record(
				AUDIT_EVENTS.tokenIssue,
				AUDIT_OUTCOMES.success,
				AUDIT_REASONS.issued,
				input.purpose,
			);

			return token;
		},
		async consume(token, purpose) {
			if (token.length !== SECRET_LENGTH) {
				return refuse(AUDIT_REASONS.malformed, purpose);
			}

			const taken = await options.store.take(await hashSecret(token));

			if (taken === undefined) {
				return refuse(AUDIT_REASONS.notFound, purpose);
			}

			if (taken.purpose !== stored(purpose)) {
				return refuse(AUDIT_REASONS.wrongPurpose, purpose);
			}

			if (!(Date.now() < taken.expiresAtMilliseconds)) {
				return refuse(AUDIT_REASONS.expired, purpose);
			}

			await record(
				AUDIT_EVENTS.tokenConsume,
				AUDIT_OUTCOMES.success,
				AUDIT_REASONS.consumed,
				purpose,
			);

			return succeed(taken.payload);
		},
	};
}
