import {
	createMemoryAccountStore,
	createMemoryEpochStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { createAuth } from "@vow-auth/core";
import {
	createLimiter,
	createMeter,
	createSealer,
	createTokens,
	type Factor,
	type Tokens,
	verifyProof,
} from "@vow-auth/core/internal";
import {
	createEmailLink,
	type EmailLinkMessage,
	type EmailLinkOptions,
} from "@vow-auth/factor-email-link";
import { durationOf, meterRuleOf } from "@vow-auth/test-support";
import { expect, test } from "vitest";

const FIFTEEN_MINUTES = 15 * 60 * 1_000;
const SECRET = "email-link-secret-0123456789abcdefghij";

/** Creates the factor the way the engine does, with capabilities of its own. */
const startEmailLink = (
	options: EmailLinkOptions,
	tokens: Tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		domain: "factor:email-link",
	}),
) => {
	const plugin = createEmailLink(options);
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});
	const instance = plugin.create({
		tokens,
		sealer: createSealer({
			secrets: [{ version: 1, value: SECRET }],
			domain: "factor:email-link",
		}),
		createLimiter: (limiterOptions) =>
			createLimiter({ ...limiterOptions, meter }),
	});
	const factor: Factor = {
		id: "email-link",
		strength: plugin.strength,
		providers: plugin.providers,
		verify: instance.verify,
	};

	return { factor, challenge: instance.api.challenge };
};

const createFixture = () => {
	const sent: EmailLinkMessage[] = [];
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		domain: "factor:email-link",
	});
	const emailLink = startEmailLink(
		{
			deliver: async (message) => {
				sent.push(message);
			},
			timeToLive: durationOf(FIFTEEN_MINUTES),
			limit: "off",
		},
		tokens,
	);
	return { emailLink, sent, tokens };
};

/** The engine with the email link as its only factor, and the tenant acme. */
const createEngine = async () => {
	const sent: EmailLinkMessage[] = [];
	const tokenStore = createMemoryTokenStore({ maximumBytes: 1_000_000 });
	const auth = createAuth({
		accounts: createMemoryAccountStore(),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore,
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: SECRET }],
		factors: {
			"email-link": createEmailLink({
				deliver: async (message) => {
					sent.push(message);
				},
				timeToLive: durationOf(FIFTEEN_MINUTES),
				limit: "off",
			}),
		},
		maximumLifeTimeMilliseconds: FIFTEEN_MINUTES,
		sessionTimeToLiveMilliseconds: FIFTEEN_MINUTES,
		registration: () => "allow",
		policy: () => "allow",
		audit: async () => undefined,
	});

	await auth.tenants.create("acme");

	const signIn = (response: string) =>
		auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email-link",
			response,
		});

	return { auth, sent, signIn, tokenStore };
};

const lastToken = (sent: readonly EmailLinkMessage[]): string => {
	const message = sent.at(-1);

	if (message === undefined) {
		throw new Error("a link must have been sent");
	}

	return message.token;
};

test("a link signs a person in end to end and revocation ends the session", async () => {
	const { auth, sent, signIn } = await createEngine();

	expect(
		(await auth.factors["email-link"].challenge("Alice@Example.COM")).ok,
	).toBe(true);
	expect(sent[0]?.email).toBe("alice@example.com");

	const signedIn = await signIn(lastToken(sent));

	if (!signedIn.ok) {
		throw new Error("the link must sign in");
	}

	expect(signedIn.value.identity).toBe("created");

	const verified = await auth.sessions.verify(signedIn.value.token);

	expect(verified.ok && verified.value.subject).toBe(signedIn.value.subject);

	await auth.sessions.revoke({
		tenant: "acme",
		scope: "user",
		id: signedIn.value.subject,
	});

	expect((await auth.sessions.verify(signedIn.value.token)).ok).toBe(false);
});

test("another spelling of the address signs in as the same account", async () => {
	const { auth, sent, signIn } = await createEngine();
	const accounts: (string | false)[] = [];

	for (const spelling of ["alice@example.com", "  ALICE@Example.Com "]) {
		await auth.factors["email-link"].challenge(spelling);

		const signedIn = await signIn(lastToken(sent));

		accounts.push(signedIn.ok && signedIn.value.account);
	}

	expect(accounts[0]).toBeTruthy();
	expect(accounts[0]).toBe(accounts[1]);
});

test("a link works once", async () => {
	const { emailLink, sent } = createFixture();

	await emailLink.challenge("alice@example.com");
	const token = lastToken(sent);

	expect((await verifyProof(emailLink.factor, token)).ok).toBe(true);
	expect((await verifyProof(emailLink.factor, token)).ok).toBe(false);
});

test("a token issued for another purpose does not open the factor", async () => {
	const { emailLink, tokens } = createFixture();
	const foreign = await tokens.issue({
		purpose: "oauth-state",
		payload: { email: "alice@example.com" },
		timeToLive: durationOf(FIFTEEN_MINUTES),
	});

	expect((await verifyProof(emailLink.factor, foreign)).ok).toBe(false);
});

test("a token without an address is refused", async () => {
	const { emailLink, tokens } = createFixture();
	const bare = await tokens.issue({
		purpose: "email-link",
		timeToLive: durationOf(FIFTEEN_MINUTES),
	});

	expect((await verifyProof(emailLink.factor, bare)).ok).toBe(false);
});

test("responses that are not a token string are refused", async () => {
	const { emailLink } = createFixture();

	for (const response of [undefined, null, 1, {}, ["a"], { token: "a" }]) {
		expect((await verifyProof(emailLink.factor, response)).ok).toBe(false);
	}
});

test("a malformed address sends nothing", async () => {
	const { emailLink, sent } = createFixture();

	for (const email of [
		"no-at-sign",
		"alice@example.com\nBcc: victim@example.com",
		"alice@example.com, bob@example.com",
		"<alice@example.com>",
		"",
	]) {
		const result = await emailLink.challenge(email);

		expect(result.ok, email).toBe(false);
	}

	expect(sent).toEqual([]);
});

test("the answer does not depend on whether the person is known", async () => {
	const { auth, sent, signIn } = await createEngine();
	const unknown =
		await auth.factors["email-link"].challenge("nobody@example.com");

	await auth.factors["email-link"].challenge("alice@example.com");
	await signIn(lastToken(sent));

	const known = await auth.factors["email-link"].challenge("alice@example.com");

	expect(unknown).toEqual(known);
});

test("a failing delivery reaches the caller", async () => {
	const emailLink = startEmailLink({
		deliver: async () => {
			throw new Error("mail is down");
		},
		timeToLive: durationOf(FIFTEEN_MINUTES),
		limit: "off",
	});

	await expect(emailLink.challenge("alice@example.com")).rejects.toThrow(
		"mail is down",
	);
});

const limitedEmailLink = (limit: EmailLinkOptions["limit"]) => {
	const sent: EmailLinkMessage[] = [];
	const emailLink = startEmailLink({
		deliver: async (message) => {
			sent.push(message);
		},
		timeToLive: durationOf(FIFTEEN_MINUTES),
		limit,
	});

	return { emailLink, sent };
};

test("links to one address are limited, and spelling variants of it share the count", async () => {
	const { emailLink, sent } = limitedEmailLink({
		rule: meterRuleOf({ limit: 2, windowMilliseconds: 60_000 }),
		scopes: ({ email }) => [
			{ tenant: "acme", actor: email, resource: "email-link" },
		],
	});

	expect((await emailLink.challenge("alice@example.com")).ok).toBe(true);
	expect((await emailLink.challenge("ALICE@Example.com")).ok).toBe(true);
	expect(await emailLink.challenge(" alice@EXAMPLE.com ")).toMatchObject({
		ok: false,
		error: { code: "rate-limited", resetsAtMilliseconds: expect.any(Number) },
	});
	expect(sent).toHaveLength(2);
	expect((await emailLink.challenge("bob@example.com")).ok).toBe(true);
});

test("an address that is refused costs no limit and sends nothing", async () => {
	const { emailLink, sent } = limitedEmailLink({
		rule: meterRuleOf({ limit: 1, windowMilliseconds: 60_000 }),
		scopes: ({ email }) => [
			{ tenant: "acme", actor: email, resource: "email-link" },
		],
	});

	for (const address of [
		"not an address",
		"a@b@c",
		"",
		`a${String.fromCharCode(0)}@example.com`,
	]) {
		expect(await emailLink.challenge(address)).toEqual({
			ok: false,
			error: "invalid-email",
		});
	}

	expect(sent).toEqual([]);
	expect((await emailLink.challenge("alice@example.com")).ok).toBe(true);
});

test("a forgotten limit stops the start", () => {
	// @ts-expect-error the limit is required
	expect(() => limitedEmailLink(undefined)).toThrow(
		/limit must be a rule with scopes/,
	);
	expect(() => limitedEmailLink("off")).not.toThrow();
});

test("through the engine a link signs in, and a token from anywhere else does not", async () => {
	const { auth, sent, signIn, tokenStore } = await createEngine();

	expect(
		(await auth.factors["email-link"].challenge("alice@example.com")).ok,
	).toBe(true);
	expect((await signIn(lastToken(sent))).ok).toBe(true);

	const elsewhere = await createTokens({
		store: tokenStore,
		domain: "factor:other",
	}).issue({
		purpose: "email-link",
		payload: { email: "victim@example.com" },
		timeToLive: durationOf(FIFTEEN_MINUTES),
	});

	expect(await signIn(elsewhere)).toEqual({
		ok: false,
		error: "invalid-proof",
	});
});
