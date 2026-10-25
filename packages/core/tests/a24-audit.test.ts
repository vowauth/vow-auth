import {
	createMemoryGrantStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AccountStore,
	AUDIT_EVENTS,
	type AuditRecord,
	type AuditSink,
	applyPlan,
	createGrants,
	createRecordSeal,
	createRecords,
	createTokens,
	evaluatePolicy,
	type Factor,
	type GrantStore,
	issueSession,
	planSignIn,
	type Result,
	succeed,
	verifyProof,
} from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { createAccounts } from "./support/accounts.js";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const SECRET = "audit-secret-0123456789abcdefghijklmnop";
const LIFE_TIME = 60_000;

const createCollector = () => {
	const records: AuditRecord[] = [];
	const sink: AuditSink = async (record) => {
		records.push(record);
	};

	return { records, sink };
};

const failingSink: AuditSink = async () => {
	throw new Error("the audit store is down");
};

const summary = (records: readonly AuditRecord[]): string[] => {
	return records.map(
		(record) => `${record.event}:${record.outcome}:${record.reason}`,
	);
};

const factorReturning = (outcome: () => Result<unknown>): Factor => ({
	id: "test-factor",
	strength: "possession",
	verify: async () => outcome(),
});

const validClaims = {
	provider: "google",
	externalId: "g-1",
	email: "alice@example.com",
	emailVerified: true,
};

const proofOf = async (claims: unknown) => {
	const result = await verifyProof(
		factorReturning(() => succeed(claims)),
		undefined,
	);

	if (!result.ok) {
		throw new Error("the proof must be minted");
	}

	return result.value;
};

const sha256 = async (text: string): Promise<string> =>
	Array.from(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
		),
		(byte) => byte.toString(16).padStart(2, "0"),
	).join("");

const createSessions = (
	audit?: AuditSink,
	store: GrantStore = createMemoryGrantStore(),
	maximumMilliseconds = LIFE_TIME,
) => {
	const records = createRecords(
		createRecordSeal({ secrets: [{ version: 1, value: SECRET }] }),
	);
	const grants = createGrants({
		store,
		records,
		idleMilliseconds: maximumMilliseconds,
		maximumMilliseconds,
		...(audit === undefined ? {} : { audit }),
	});
	const issue = async (subject: string) =>
		grants.issue(await bornSession(subject), {
			accountId: `acc_${subject}`,
			tenant: "acme",
			subjectId: subject,
			device: "laptop",
			proofs: [await proofOf(validClaims)],
		});

	return { grants, issue, records, store };
};

const bornSession = async (subject: string) => {
	const decision = await evaluatePolicy(subject, () => "allow");
	const session = issueSession(decision);

	if (!session.ok) {
		throw new Error("an allowed session must be born");
	}

	return session.value;
};

test("policy decisions are recorded with their reason", async () => {
	const { records, sink } = createCollector();

	await evaluatePolicy("u1", () => "allow", { audit: sink, tenant: "acme" });
	await evaluatePolicy("u2", () => "nope", { audit: sink, tenant: "acme" });
	await evaluatePolicy(
		"u3",
		() => {
			throw new Error("boom");
		},
		{ audit: sink },
	);

	expect(summary(records)).toEqual([
		"policy.evaluate:success:allow",
		"policy.evaluate:refusal:not-allowed",
		"policy.evaluate:refusal:policy-error",
	]);
	expect(records.map((record) => [record.tenant, record.subject])).toEqual([
		["acme", "u1"],
		["acme", "u2"],
		["", "u3"],
	]);
});

test("proofs are recorded with the reason a refusal has, without the email", async () => {
	const { records, sink } = createCollector();
	const run = (factor: Factor) =>
		verifyProof(factor, undefined, { audit: sink });

	await run(factorReturning(() => succeed(validClaims)));
	await run({
		id: "rejecting",
		strength: "possession",
		verify: async () => ({ ok: false, error: "bad-code" }),
	});
	await run({
		id: "throwing",
		strength: "possession",
		verify: async () => {
			throw new Error("boom");
		},
	});
	await run(factorReturning(() => succeed({ provider: "p" })));
	await run(
		factorReturning(() => succeed({ ...validClaims, email: "not-an-email" })),
	);

	expect(summary(records)).toEqual([
		"proof.verify:success:verified",
		"proof.verify:refusal:factor-rejected",
		"proof.verify:refusal:factor-error",
		"proof.verify:refusal:invalid-claims",
		"proof.verify:refusal:invalid-email",
	]);
	expect(records[0]?.detail).toEqual({
		factor: "test-factor",
		provider: "google",
		emailVerified: "true",
	});
	expect(JSON.stringify(records)).not.toContain("alice@example.com");
});

const signInOf = async (
	accounts: { readonly store: AccountStore },
	records: Parameters<typeof planSignIn>[0]["records"],
	tenant: string,
	proof: unknown,
	audit: AuditSink,
) => {
	const options = {
		store: accounts.store,
		records,
		trustedProviders: ["email", "github"],
		audit,
	};
	const plan = await planSignIn(options, tenant, proof);

	if (!plan.ok) {
		return;
	}

	await applyPlan({ ...options, revoke: async () => undefined }, plan.value);
};

test("identity resolution is recorded for every outcome and refusal", async () => {
	const { records, sink } = createCollector();
	const accounts = await createAccounts();
	const first = await proofOf({ ...validClaims, provider: "email" });
	const other = await proofOf({
		...validClaims,
		provider: "github",
		externalId: "gh-1",
	});

	for (const [tenant, proof] of [
		["acme", first],
		["acme", first],
		["acme", other],
		["nowhere", first],
	] as const) {
		await signInOf(accounts, accounts.records, tenant, proof, sink);
	}

	expect(summary(records)).toEqual([
		"identity.resolve:success:created",
		"identity.resolve:success:existing",
		"identity.resolve:success:linked",
		"identity.resolve:refusal:not-found",
	]);
	expect(records[0]?.subject).not.toBe("");
	expect(records[0]?.subject).toBe(records[1]?.subject);
	expect(records[2]?.subject).toBe(records[0]?.subject);
	expect(records[3]?.tenant).toBe("nowhere");
	expect(records.slice(0, 3).every((record) => record.tenant === "acme")).toBe(
		true,
	);
});

test("a token refusal is generic to the caller and exact in the audit", async () => {
	const { records, sink } = createCollector();
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		audit: sink,
	});
	const issue = (purpose: string, timeToLiveMilliseconds = 1_000) =>
		tokens.issue({ purpose, timeToLive: durationOf(timeToLiveMilliseconds) });

	const ok = await issue("email-link");
	const wrong = await issue("oauth-state");
	const expiring = await issue("email-link", 500);
	records.length = 0;

	const results = [
		await tokens.consume("short", "email-link"),
		await tokens.consume("0".repeat(64), "email-link"),
		await tokens.consume(wrong, "email-link"),
	];
	vi.setSystemTime(1_500);
	results.push(await tokens.consume(expiring, "email-link"));
	results.push(await tokens.consume(ok, "email-link"));

	expect(results.map((result) => (result.ok ? "ok" : result.error))).toEqual([
		"invalid-token",
		"invalid-token",
		"invalid-token",
		"invalid-token",
		"ok",
	]);
	expect(summary(records)).toEqual([
		"token.consume:refusal:malformed",
		"token.consume:refusal:not-found",
		"token.consume:refusal:wrong-purpose",
		"token.consume:refusal:not-found",
		"token.consume:success:consumed",
	]);
	expect(
		records.every((record) => record.detail.purpose === "email-link"),
	).toBe(true);
});

test("sessions record issue, refusals with their reason, and revocation", async () => {
	const { records, sink } = createCollector();
	const { grants, issue } = createSessions(sink);
	const issued = await issue("alice");

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	expect((await grants.verify(issued.value, "acme")).ok).toBe(true);
	expect(summary(records)).toEqual(["session.issue:success:issued"]);

	await grants.verify("1.garbage", "acme");
	await grants.verify(`vas_${"0".repeat(64)}`, "acme");
	await grants.revoke({ scope: "device", id: "laptop" });
	await grants.verify(issued.value, "acme");

	expect(summary(records)).toEqual([
		"session.issue:success:issued",
		"session.verify:refusal:malformed",
		"session.verify:refusal:not-found",
		"session.revoke:success:revoked",
		"session.verify:refusal:revoked",
	]);
	expect(records[0]).toMatchObject({
		tenant: "acme",
		subject: "alice",
		detail: { account: "acc_alice", device: "laptop" },
	});
	expect(records[3]).toMatchObject({
		detail: { scope: "device", id: "laptop", grants: "2" },
	});
	expect(records[4]).toMatchObject({
		tenant: "acme",
		detail: { scope: "session" },
	});
});

test("an expired session, an unknown token and a grant written past the engine are told apart in the audit", async () => {
	const { records, sink } = createCollector();
	const store = createMemoryGrantStore();
	const { grants, issue } = createSessions(sink, store, 1_000);
	const issued = await issue("alice");

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	const forged = `vas_${"f".repeat(64)}`;

	await store.createSession(
		{
			id: "forged",
			kind: "session",
			tokenHash: await sha256(forged),
			accountId: "acc_mallory",
			tenant: undefined,
			subjectId: undefined,
			device: "laptop",
			agent: undefined,
			parentId: undefined,
			sessionId: undefined,
			proofs: "[]",
			authenticatedAtMilliseconds: Date.now(),
			expiresAtMilliseconds: Date.now() + LIFE_TIME,
			idleExpiresAtMilliseconds: undefined,
			revoked: false,
			seal: "1.AAAA",
		},
		{
			id: "forged-entry",
			kind: "tenant",
			tokenHash: undefined,
			accountId: "acc_mallory",
			tenant: "acme",
			subjectId: "mallory",
			device: "laptop",
			agent: undefined,
			parentId: "forged",
			sessionId: "forged",
			proofs: undefined,
			authenticatedAtMilliseconds: Date.now(),
			expiresAtMilliseconds: Date.now() + LIFE_TIME,
			idleExpiresAtMilliseconds: undefined,
			revoked: false,
			seal: "1.AAAA",
		},
	);
	records.length = 0;
	vi.setSystemTime(2_500);
	await grants.verify(issued.value, "acme");
	await grants.verify(`${issued.value.slice(0, -2)}00`, "acme");
	await grants.verify(forged, "acme");
	await grants.verify("garbage", "acme");

	expect(summary(records)).toEqual([
		"session.verify:refusal:expired",
		"session.verify:refusal:not-found",
		"session.verify:refusal:invalid-record",
		"session.verify:refusal:malformed",
	]);
});

test("a store that returns an expired record gets the reason expired", async () => {
	const { records, sink } = createCollector();
	const tokens = createTokens({
		store: {
			put: async () => undefined,
			take: async () => ({
				purpose: JSON.stringify(["core", "email-link"]),
				payload: {},
				expiresAtMilliseconds: 500,
			}),
		},
		audit: sink,
	});

	const result = await tokens.consume("0".repeat(64), "email-link");

	expect(!result.ok && result.error).toBe("invalid-token");
	expect(summary(records)).toEqual(["token.consume:refusal:expired"]);
});

test("no record carries a secret", async () => {
	const { records, sink } = createCollector();
	const { grants, issue } = createSessions(sink);
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		audit: sink,
	});
	const link = await tokens.issue({
		purpose: "email-link",
		payload: { email: "alice@example.com" },
		timeToLive: durationOf(1_000),
	});

	await tokens.consume(link, "email-link");

	const issued = await issue("alice");

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	await grants.verify(`${issued.value}x`, "acme");
	await grants.verify(issued.value, "acme");

	const serialized = JSON.stringify(records);

	expect(serialized).not.toContain(link);
	expect(serialized).not.toContain(issued.value);
	expect(serialized).not.toContain(await sha256(issued.value));
	expect(serialized).not.toContain(SECRET);
	expect(serialized).not.toContain("alice@example.com");
});

test("a sink cannot change a decision or leak changes into later records", async () => {
	const seen: AuditRecord[] = [];
	const meddling: AuditSink = async (record) => {
		seen.push(record);
		Reflect.set(record, "outcome", "refusal");
		Reflect.set(record.detail, "factor", "forged");
	};

	const decision = await evaluatePolicy("u1", () => "allow", {
		audit: meddling,
	});
	const proof = await verifyProof(
		factorReturning(() => succeed(validClaims)),
		undefined,
		{ audit: meddling },
	);

	expect(decision.kind).toBe("allow");
	expect(proof.ok).toBe(true);
	expect(seen[1]?.detail.factor).toBe("forged");

	const { records, sink } = createCollector();
	await verifyProof(
		factorReturning(() => succeed(validClaims)),
		undefined,
		{ audit: sink },
	);

	expect(records[0]?.detail.factor).toBe("test-factor");
});

test("a failing sink means no allow decision and no proof", async () => {
	await expect(
		evaluatePolicy("u1", () => "allow", { audit: failingSink }),
	).rejects.toThrow("the audit store is down");
	await expect(
		verifyProof(
			factorReturning(() => succeed(validClaims)),
			undefined,
			{
				audit: failingSink,
			},
		),
	).rejects.toThrow("the audit store is down");
});

test("a failing sink prevents a link, a token and a session token", async () => {
	const accounts = await createAccounts();
	const linkSpy = vi.fn(accounts.store.linkIdentity);
	const store: AccountStore = { ...accounts.store, linkIdentity: linkSpy };

	await signInOf(
		{ store },
		accounts.records,
		"acme",
		await proofOf({ ...validClaims, provider: "email" }),
		async () => undefined,
	);

	await expect(
		signInOf(
			{ store },
			accounts.records,
			"acme",
			await proofOf({ ...validClaims, provider: "github" }),
			failingSink,
		),
	).rejects.toThrow("the audit store is down");
	expect(linkSpy).not.toHaveBeenCalled();

	const tokenStore = createMemoryTokenStore({ maximumBytes: 1_000_000 });
	const tokens = createTokens({ store: tokenStore, audit: failingSink });

	await expect(
		tokens.issue({ purpose: "email-link", timeToLive: durationOf(1_000) }),
	).rejects.toThrow("the audit store is down");

	const failing = createSessions(failingSink);

	await expect(failing.issue("alice")).rejects.toThrow(
		"the audit store is down",
	);
	expect(
		await failing.store.findSession(`vas_${"0".repeat(64)}`, undefined),
	).toBeUndefined();
});

test("a failing sink gives no payload for a redemption and the token stays spent", async () => {
	const store = createMemoryTokenStore({ maximumBytes: 1_000_000 });
	const issuing = createTokens({ store });
	const token = await issuing.issue({
		purpose: "email-link",
		timeToLive: durationOf(1_000),
	});

	await expect(
		createTokens({ store, audit: failingSink }).consume(token, "email-link"),
	).rejects.toThrow("the audit store is down");
	expect((await issuing.consume(token, "email-link")).ok).toBe(false);
});

test("a failing sink never blocks a revocation, and the caller still learns of it", async () => {
	const store = createMemoryGrantStore();
	const quiet = createSessions(undefined, store);
	const loud = createSessions(failingSink, store);
	const issued = await quiet.issue("alice");

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	await expect(
		loud.grants.revoke({ scope: "tenant", tenant: "acme" }),
	).rejects.toThrow("the audit store is down");
	expect((await quiet.grants.verify(issued.value, "acme")).ok).toBe(false);
});

test("a refusal still reaches the caller as a failure when the sink is down", async () => {
	const { grants } = createSessions(failingSink);

	await expect(grants.verify("1.garbage", "acme")).rejects.toThrow(
		"the audit store is down",
	);
});

test("the core reports exactly the documented events", () => {
	expect(Object.values(AUDIT_EVENTS).sort()).toEqual([
		"account.delete",
		"account.evict",
		"delegation.grant",
		"identity.resolve",
		"membership.change",
		"meter.consume",
		"policy.evaluate",
		"proof.verify",
		"seal.unseal",
		"session.issue",
		"session.revoke",
		"session.verify",
		"signin.continue",
		"tenant.change",
		"token.consume",
		"token.issue",
	]);
});
