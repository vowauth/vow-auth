import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { SECRET_LENGTH } from "../shared/constants.js";
import { own } from "../shared/own.js";
import { generateSecret, hashSecret } from "../shared/secret.js";
import type { TokenStore } from "./token-store.js";

/** Options for creating the tokens primitive. */
export type TokensOptions = {
	readonly store: TokenStore;
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
 * `invalid-token` error, so a caller cannot learn why a token was refused.
 */
export function createTokens(options: TokensOptions): Tokens {
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
				return fail(ERROR_CODES.invalidToken);
			}

			const record = await options.store.take(await hashSecret(token));

			if (
				record === undefined ||
				record.purpose !== purpose ||
				!(Date.now() < record.expiresAtMilliseconds)
			) {
				return fail(ERROR_CODES.invalidToken);
			}

			return succeed(record.payload);
		},
	};
}
