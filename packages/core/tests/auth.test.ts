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
	type Factor,
	succeed,
} from "@vow-auth/core";
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
		timeToLiveMilliseconds: 1_000,
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
		{ limit: 1, windowMilliseconds: 1_000 },
	);
	await auth.meter.consume(
		{ tenant: "acme", actor: "alice", resource: "email-link" },
		{ limit: 1, windowMilliseconds: 1_000 },
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
		auth.tokens.issue({ purpose: "p", timeToLiveMilliseconds: 1_000 }),
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
