import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryOutboxStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	createEmit,
	createOutboxWorker,
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
		timeToLiveMilliseconds: FIFTEEN_MINUTES,
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
		timeToLiveMilliseconds: FIFTEEN_MINUTES,
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
		timeToLiveMilliseconds: FIFTEEN_MINUTES,
	});

	expect((await verifyProof(emailLink.factor, foreign)).ok).toBe(false);
});

test("a token without an address is refused", async () => {
	const { emailLink, tokens } = createFixture();
	const bare = await tokens.issue({
		purpose: "email-link",
		timeToLiveMilliseconds: FIFTEEN_MINUTES,
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
		timeToLiveMilliseconds: FIFTEEN_MINUTES,
	});

	await expect(emailLink.challenge("alice@example.com")).rejects.toThrow(
		"mail is down",
	);
});

test("delivery through the outbox keeps the sign-in alive while the mail provider is down", async () => {
	const outbox = createMemoryOutboxStore();
	const emit = createEmit(outbox);
	const emailLink = createEmailLink({
		tokens: createTokens({
			store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		}),
		deliver: async (message) => {
			const recorded = await emit({
				type: "email.send",
				payload: { to: message.email, token: message.token },
			});

			if (!recorded.ok) {
				throw new Error("the outbox must accept the event");
			}
		},
		timeToLiveMilliseconds: FIFTEEN_MINUTES,
	});
	const sentMails: string[] = [];
	let providerIsUp = false;
	const worker = createOutboxWorker({
		store: outbox,
		handlers: {
			"email.send": async (event) => {
				if (!providerIsUp) {
					throw new Error("mail provider is down");
				}

				sentMails.push(event.payload.token ?? "");
			},
		},
		batchSize: 10,
		leaseMilliseconds: 1_000,
		retryDelayMilliseconds: 1,
		maximumAttempts: 5,
	});

	expect((await emailLink.challenge("alice@example.com")).ok).toBe(true);
	expect((await worker.runOnce()).retried).toBe(1);

	providerIsUp = true;
	await new Promise((resolve) => setTimeout(resolve, 5));
	expect((await worker.runOnce()).completed).toBe(1);

	const proof = await verifyProof(emailLink.factor, sentMails[0]);
	expect(proof.ok).toBe(true);
});
