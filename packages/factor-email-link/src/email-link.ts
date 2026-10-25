import {
	applyLimit,
	assertLimitRule,
	canonicalizeEmail,
	type Duration,
	EMAIL_PROVIDER,
	ERROR_CODES,
	type FactorPlugin,
	fail,
	type Limit,
	type LimitRule,
	type MeterRefusal,
	NO_LIMIT,
	type Result,
	succeed,
} from "@vow-auth/core";

const EMAIL_LINK_PURPOSE = "email-link";

/** What the application sends: the address and the secret to put into the link. */
export type EmailLinkMessage = {
	readonly email: string;
	readonly token: string;
};

/** Options for creating the email link factor. */
export type EmailLinkOptions = {
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
	 * answer is required: a rule and the scopes to count, or `"off"` when the
	 * caller limits it already. The engine counts it in its meter store.
	 */
	readonly limit: LimitRule<{ readonly email: string }> | typeof NO_LIMIT;
};

/** What the application may call on the email link factor. */
export type EmailLink = {
	/**
	 * Sends a link to the address. The answer does not depend on whether the
	 * address belongs to a known subject, so it reveals nothing about accounts.
	 * The link goes to the mailbox only: nobody else ever holds the token.
	 */
	challenge(email: string): Promise<Result<undefined, string | MeterRefusal>>;
};

/**
 * Creates the email link factor, to give to `createAuth`. The token is issued
 * with the tokens of this factor alone, bound to the canonical address and
 * redeemed once, so nothing but a link from the mailbox opens it. The factor
 * only proves ownership of the mailbox and claims identities of the provider
 * `email`; it never creates a session or links an account.
 */
export function createEmailLink(
	options: EmailLinkOptions,
): FactorPlugin<EmailLink> {
	assertLimitRule("limit", options.limit);

	return {
		strength: "possession",
		providers: [EMAIL_PROVIDER],
		create({ tokens, createLimiter }) {
			const limit: Limit<{ readonly email: string }> =
				options.limit === NO_LIMIT ? NO_LIMIT : createLimiter(options.limit);

			return {
				async verify(response) {
					if (typeof response !== "string") {
						return fail(ERROR_CODES.invalidToken);
					}

					const consumed = await tokens.consume(response, EMAIL_LINK_PURPOSE);

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
				api: {
					async challenge(email) {
						const canonical = canonicalizeEmail(email);

						if (canonical === undefined) {
							return fail(ERROR_CODES.invalidEmail);
						}

						const allowed = await applyLimit(limit, {
							email: canonical.address,
						});

						if (!allowed.ok) {
							return fail(allowed.error);
						}

						const token = await tokens.issue({
							purpose: EMAIL_LINK_PURPOSE,
							payload: { email: canonical.address },
							timeToLive: options.timeToLive,
						});

						await options.deliver({ email: canonical.address, token });

						return succeed(undefined);
					},
				},
			};
		},
	};
}
