import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AuditRecord,
	type AuditSink,
	type AuthOptions,
	createAuth,
	defineDuration,
	type Factor,
	requireFactor,
	succeed,
} from "@vow-auth/core";
import { durationOf, meterRuleOf } from "@vow-auth/test-support";
import { expect, test } from "vitest";

const LIFE_TIME = 60_000;

const optionsWith = (audit: AuditSink): AuthOptions => ({
	identities: createMemoryIdentityStore(),
	epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
	tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
	meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	secrets: [{ version: 1, value: "auth-secret-0123456789abcdefghijklmnop" }],
	maximumLifeTimeMilliseconds: LIFE_TIME,
	sessionTimeToLiveMilliseconds: LIFE_TIME,
	policy: () => "allow",
	audit,
});

const emailFactor: Factor = {
	id: "email",
	strength: "possession",
	verify: async () =>
		succeed({
			provider: "email",
			externalId: "alice@example.com",
			email: "alice@example.com",
			emailVerified: true,
		}),
};

test("the audit sink is required, and a missing one is refused when the types are bypassed", () => {
	const { audit: _omitted, ...withoutAudit } = optionsWith(
		async () => undefined,
	);

	expect(() => {
		// @ts-expect-error the audit sink is required
		createAuth(withoutAudit);
	}).toThrow(TypeError);
	expect(() =>
		Reflect.apply(createAuth, undefined, [{ ...withoutAudit, audit: "log" }]),
	).toThrow(TypeError);
});

test("one sink reaches every part of the core", async () => {
	const records: AuditRecord[] = [];
	const auth = createAuth(
		optionsWith(async (record) => {
			records.push(record);
		}),
	);

	const link = await auth.tokens.issue({
		purpose: "email-link",
		timeToLive: durationOf(1_000),
	});

	await auth.tokens.consume(link, "email-link");
	await auth.sealer.unseal("1.garbage", "oauth-state");

	const signedIn = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: emailFactor,
		response: undefined,
	});

	if (!signedIn.ok) {
		throw new Error("the sign in must pass");
	}

	await auth.meter.consume(
		{ tenant: "acme", actor: "alice", resource: "email-link" },
		meterRuleOf({ limit: 1, windowMilliseconds: 1_000 }),
	);
	await auth.meter.consume(
		{ tenant: "acme", actor: "alice", resource: "email-link" },
		meterRuleOf({ limit: 1, windowMilliseconds: 1_000 }),
	);
	await auth.sessions.verify("1.garbage");
	await auth.sessions.revoke({ tenant: "acme", scope: "tenant" });
	await auth.mutateIdentity("acme", signedIn.value.subject, { type: "delete" });

	expect([...new Set(records.map((record) => record.event))].sort()).toEqual([
		"identity.mutate",
		"identity.resolve",
		"meter.consume",
		"policy.evaluate",
		"proof.verify",
		"seal.unseal",
		"session.issue",
		"session.revoke",
		"session.verify",
		"token.consume",
		"token.issue",
	]);
});

test("a failing sink stops every part that grants something", async () => {
	const auth = createAuth(
		optionsWith(async () => {
			throw new Error("the audit store is down");
		}),
	);

	await expect(
		auth.tokens.issue({ purpose: "p", timeToLive: durationOf(1_000) }),
	).rejects.toThrow("the audit store is down");
	await expect(
		auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: emailFactor,
			response: undefined,
		}),
	).rejects.toThrow("the audit store is down");
});

test("the sessions part can check and revoke but not issue", () => {
	const auth = createAuth(optionsWith(async () => undefined));

	expect(Object.keys(auth.sessions).sort()).toEqual(["revoke", "verify"]);
});

const hour = () => {
	const duration = defineDuration(3_600_000);

	if (!duration.ok) {
		throw new Error("an hour is a valid duration");
	}

	return duration.value;
};

test("what the application seals never opens as a session, however it is shaped", async () => {
	const auth = createAuth(optionsWith(async () => undefined));
	const now = Date.now();
	const future = now + 10 ** 12;
	const forged = await auth.sealer.seal({
		purpose: "session",
		payload: {
			chain: JSON.stringify([
				{ scope: "tenant", id: "acme", stamp: future },
				{ scope: "user", id: "anyone", stamp: future },
				{ scope: "device", id: "laptop", stamp: future },
				{ scope: "session", id: "s-1", stamp: future },
			]),
			expiresAtMilliseconds: String(now + 3_600_000),
			authenticatedAtMilliseconds: String(now),
			methods: JSON.stringify(["totp"]),
		},
		timeToLive: hour(),
	});
	const agent = await auth.sealer.seal({
		purpose: "agent",
		payload: {
			chain: JSON.stringify([
				{ scope: "tenant", id: "acme", stamp: future },
				{ scope: "user", id: "anyone", stamp: future },
				{ scope: "agent", id: "bot", stamp: future },
				{ scope: "delegation", id: "d-1", stamp: future },
			]),
			expiresAtMilliseconds: String(now + 3_600_000),
			delegatedAtMilliseconds: String(now),
		},
		timeToLive: hour(),
	});

	expect(await auth.sessions.verify(forged)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.agents.verify(agent)).toEqual({
		ok: false,
		error: "invalid-session",
	});
});

test("a token the application issues never continues a sign in", async () => {
	const records: AuditRecord[] = [];
	const auth = createAuth({
		...optionsWith(async (record) => {
			records.push(record);
		}),
		stepUpTimeToLiveMilliseconds: 60_000,
		policy: () => requireFactor("email"),
	});
	const forged = await auth.tokens.issue({
		purpose: "sign-in-continuation",
		payload: { tenant: "acme", device: "laptop", factor: "email" },
		timeToLive: hour(),
	});

	records.length = 0;

	expect(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: emailFactor,
			response: undefined,
			continuation: forged,
		}),
	).toEqual({ ok: false, error: "invalid-token" });
	expect(records[0]).toMatchObject({
		event: "token.consume",
		outcome: "refusal",
		reason: "wrong-purpose",
	});
});
