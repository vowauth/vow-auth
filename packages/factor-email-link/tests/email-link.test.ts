import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { createLimiter } from "@vow-auth/core";
import {
	createMeter,
	createSealer,
	createSessionTokens,
	createTokens,
	evaluatePolicy,
	issueSession,
	resolveIdentity,
	verifyProof,
} from "@vow-auth/core/internal";
import {
	createEmailLink,
	type EmailLinkMessage,
} from "@vow-auth/factor-email-link";
import { durationOf, meterRuleOf } from "@vow-auth/test-support";
import { expect, test } from "vitest";

const FIFTEEN_MINUTES = 15 * 60 * 1_000;

const createFixture = () => {
	const sent: EmailLinkMessage[] = [];
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
	});
	const emailLink = createEmailLink({
		tokens,
		deliver: async (message) => {
			sent.push(message);
		},
		timeToLive: durationOf(FIFTEEN_MINUTES),
		limit: "off",
	});
	const identities = createMemoryIdentityStore();
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: "session-secret-0123456789abcdefghijk" }],
		}),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		maximumLifeTimeMilliseconds: FIFTEEN_MINUTES,
	});

	return { emailLink, identities, sent, sessionTokens, tokens };
};

const lastToken = (sent: readonly EmailLinkMessage[]): string => {
	const message = sent.at(-1);

	if (message === undefined) {
		throw new Error("a link must have been sent");
	}

	return message.token;
};

test("a link signs a person in end to end and revocation ends the session", async () => {
	const { emailLink, identities, sent, sessionTokens } = createFixture();

	expect((await emailLink.challenge("Alice@Example.COM")).ok).toBe(true);
	expect(sent[0]?.email).toBe("alice@example.com");

	const proof = await verifyProof(emailLink.factor, lastToken(sent));
	expect(proof.ok).toBe(true);

	if (!proof.ok) {
		return;
	}

	const resolution = await resolveIdentity(identities, "acme", proof.value);
	expect(resolution.ok && resolution.value.outcome).toBe("created");

	if (!resolution.ok) {
		return;
	}

	const decision = await evaluatePolicy(
		resolution.value.subjectId,
		() => "allow",
	);
	const session = issueSession(decision);
	expect(session.ok).toBe(true);

	if (!session.ok) {
		return;
	}

	const token = await sessionTokens.issue(session.value, {
		tenant: "acme",
		device: "laptop",
		timeToLive: durationOf(FIFTEEN_MINUTES),
		methods: ["test"],
	});

	if (!token.ok) {
		throw new Error("a born session must get a token");
	}

	const verified = await sessionTokens.verify(token.value);
	expect(verified.ok && verified.value.subject).toBe(
		resolution.value.subjectId,
	);

	await sessionTokens.revoke({
		tenant: "acme",
		scope: "user",
		id: resolution.value.subjectId,
	});

	expect((await sessionTokens.verify(token.value)).ok).toBe(false);
});

test("another spelling of the address signs in as the same subject", async () => {
	const { emailLink, identities, sent } = createFixture();
	const subjects: (string | false)[] = [];

	for (const spelling of ["alice@example.com", "  ALICE@Example.Com "]) {
		await emailLink.challenge(spelling);
		const proof = await verifyProof(emailLink.factor, lastToken(sent));
		const resolution = proof.ok
			? await resolveIdentity(identities, "acme", proof.value)
			: undefined;

		subjects.push(resolution?.ok === true && resolution.value.subjectId);
	}

	expect(subjects[0]).toBeTruthy();
	expect(subjects[0]).toBe(subjects[1]);
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

test("the answer does not depend on whether the subject is known", async () => {
	const { emailLink, identities, sent } = createFixture();
	const unknown = await emailLink.challenge("nobody@example.com");

	await emailLink.challenge("alice@example.com");
	const proof = await verifyProof(emailLink.factor, lastToken(sent));

	if (proof.ok) {
		await resolveIdentity(identities, "acme", proof.value);
	}

	const known = await emailLink.challenge("alice@example.com");

	expect(unknown).toEqual(known);
});

test("a failing delivery reaches the caller", async () => {
	const emailLink = createEmailLink({
		tokens: createTokens({
			store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		}),
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

const limitedEmailLink = (
	limit: Parameters<typeof createEmailLink>[0]["limit"],
) => {
	const sent: EmailLinkMessage[] = [];
	const emailLink = createEmailLink({
		tokens: createTokens({
			store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		}),
		deliver: async (message) => {
			sent.push(message);
		},
		timeToLive: durationOf(FIFTEEN_MINUTES),
		limit,
	});

	return { emailLink, sent };
};

test("links to one address are limited, and spelling variants of it share the count", async () => {
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});
	const { emailLink, sent } = limitedEmailLink(
		createLimiter({
			meter,
			rule: meterRuleOf({ limit: 2, windowMilliseconds: 60_000 }),
			scopes: ({ email }) => [
				{ tenant: "acme", actor: email, resource: "email-link" },
			],
		}),
	);

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
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});
	const { emailLink, sent } = limitedEmailLink(
		createLimiter({
			meter,
			rule: meterRuleOf({ limit: 1, windowMilliseconds: 60_000 }),
			scopes: ({ email }) => [
				{ tenant: "acme", actor: email, resource: "email-link" },
			],
		}),
	);

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
	expect(() => limitedEmailLink(undefined)).toThrow(/limit must be a limiter/);
	expect(() => limitedEmailLink("off")).not.toThrow();
});
