import {
	applyLimit,
	assertLimit,
	canonicalizeEmail,
	type Duration,
	EMAIL_PROVIDER,
	ERROR_CODES,
	type Factor,
	fail,
	type Limit,
	type MeterRefusal,
	type Result,
	succeed,
	type Tokens,
} from "@vow-auth/core";

const EMAIL_LINK_PURPOSE = "email-link";

/** What the application sends: the address and the secret to put into the link. */
export type EmailLinkMessage = {
	readonly email: string;
	readonly token: string;
};

/** Options for creating the email link factor. */
export type EmailLinkOptions = {
	readonly tokens: Tokens;
	/**
	 * Delivers the link. Keep it short: enqueue the message instead of calling
	 * a mail provider inside the request. A thrown error reaches the caller of
	 * `challenge`.
	 */
	readonly deliver: (message: EmailLinkMessage) => Promise<void>;
	/** How long a link stays valid; create it with `defineDuration`. */
	readonly timeToLive: Duration;
	/**
	 * How often a link may be sent to one address. Asking for a link costs
	 * nothing for an anonymous caller and reaches a stranger's mailbox, so the
	 * answer is required: a limiter made with `createLimiter`, or `"off"`
	 * when the caller limits it already.
	 */
	readonly limit: Limit<{ readonly email: string }>;
};

/** A passwordless sign-in by a link sent to an email address. */
export type EmailLink = {
	/** Proves possession of the mailbox; pass it to `verifyProof` with the token from the link. */
	readonly factor: Factor;
	/**
	 * Sends a link to the address. The answer does not depend on whether the
	 * address belongs to a known subject, so it reveals nothing about accounts.
	 */
	challenge(email: string): Promise<Result<undefined, string | MeterRefusal>>;
};

/**
 * Creates the email link factor. The token is bound to the canonical address
 * and to the purpose `email-link`, so it opens nothing else, and it is
 * redeemed once. The factor only proves ownership of the mailbox; it never
 * creates a session or links an account.
 */
export function createEmailLink(options: EmailLinkOptions): EmailLink {
	assertLimit("limit", options.limit);

	return {
		factor: {
			id: EMAIL_LINK_PURPOSE,
			strength: "possession",
			async verify(response) {
				if (typeof response !== "string") {
					return fail(ERROR_CODES.invalidToken);
				}

				const consumed = await options.tokens.consume(
					response,
					EMAIL_LINK_PURPOSE,
				);

				if (!consumed.ok) {
					return consumed;
				}

				const email = Object.hasOwn(consumed.value, "email")
					? consumed.value.email
					: undefined;

				if (email === undefined) {
					return fail(ERROR_CODES.invalidToken);
				}

				return succeed({
					provider: EMAIL_PROVIDER,
					externalId: email,
					email,
					emailVerified: true,
				});
			},
		},
		async challenge(email) {
			const canonical = canonicalizeEmail(email);

			if (canonical === undefined) {
				return fail(ERROR_CODES.invalidEmail);
			}

			const allowed = await applyLimit(options.limit, {
				email: canonical.address,
			});

			if (!allowed.ok) {
				return fail(allowed.error);
			}

			const token = await options.tokens.issue({
				purpose: EMAIL_LINK_PURPOSE,
				payload: { email: canonical.address },
				timeToLive: options.timeToLive,
			});

			await options.deliver({ email: canonical.address, token });

			return succeed(undefined);
		},
	};
}
