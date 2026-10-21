import {
	canonicalizeEmail,
	ERROR_CODES,
	type Factor,
	fail,
	type Result,
	succeed,
	type Tokens,
} from "@vow-auth/core";

const EMAIL_LINK_PURPOSE = "email-link";
const EMAIL_PROVIDER = "email";

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
	readonly timeToLiveMilliseconds: number;
};

/** A passwordless sign-in by a link sent to an email address. */
export type EmailLink = {
	/** Proves possession of the mailbox; pass it to `verifyProof` with the token from the link. */
	readonly factor: Factor;
	/**
	 * Sends a link to the address. The answer does not depend on whether the
	 * address belongs to a known subject, so it reveals nothing about accounts.
	 */
	challenge(email: string): Promise<Result<undefined>>;
};

/**
 * Creates the email link factor. The token is bound to the canonical address
 * and to the purpose `email-link`, so it opens nothing else, and it is
 * redeemed once. The factor only proves ownership of the mailbox; it never
 * creates a session or links an account.
 */
export function createEmailLink(options: EmailLinkOptions): EmailLink {
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

			const token = await options.tokens.issue({
				purpose: EMAIL_LINK_PURPOSE,
				payload: { email: canonical },
				timeToLiveMilliseconds: options.timeToLiveMilliseconds,
			});

			await options.deliver({ email: canonical, token });

			return succeed(undefined);
		},
	};
}
