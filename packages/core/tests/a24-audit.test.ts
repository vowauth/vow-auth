import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	AUDIT_EVENTS,
	type AuditRecord,
	type AuditSink,
	createSealer,
	createSessionTokens,
	createTokens,
	evaluatePolicy,
	type Factor,
	type IdentityStore,
	issueSession,
	type Result,
	resolveIdentity,
	succeed,
	verifyProof,
} from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/store-contracts";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

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

const createSessions = (audit?: AuditSink) => {
	const sealer = createSealer({ secrets: [{ version: 1, value: SECRET }] });
	const sessionTokens = createSessionTokens({
		sealer,
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		maximumLifeTimeMilliseconds: LIFE_TIME,
		...(audit === undefined ? {} : { audit }),
	});

	return { sealer, sessionTokens };
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

test("identity resolution is recorded for every outcome and refusal", async () => {
	const { records, sink } = createCollector();
	const store = createMemoryIdentityStore();
	const first = await proofOf({ ...validClaims, provider: "email" });
	const other = await proofOf({
		...validClaims,
		provider: "github",
		externalId: "gh-1",
	});

	await resolveIdentity(store, "acme", first, { audit: sink });
	await resolveIdentity(store, "acme", first, { audit: sink });
	await resolveIdentity(store, "acme", other, { audit: sink });
	await resolveIdentity(store, "acme", { forged: true }, { audit: sink });

	expect(summary(records)).toEqual([
		"identity.resolve:success:created",
		"identity.resolve:success:existing",
		"identity.resolve:success:linked",
		"identity.resolve:refusal:no-proof",
	]);
	expect(records[0]?.subject).not.toBe("");
	expect(records[0]?.subject).toBe(records[1]?.subject);
	expect(records[2]?.subject).toBe(records[0]?.subject);
	expect(records.every((record) => record.tenant === "acme")).toBe(true);
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

test("session tokens record issue, refusals with their reason, and revocation", async () => {
	const { records, sink } = createCollector();
	const { sealer, sessionTokens } = createSessions(sink);
	const session = await bornSession("alice");
	const issued = await sessionTokens.issue(session, {
		tenant: "acme",
		device: "laptop",
		timeToLive: durationOf(LIFE_TIME),
		methods: ["test"],
	});

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	expect((await sessionTokens.verify(issued.value)).ok).toBe(true);
	expect(summary(records)).toEqual(["session.issue:success:issued"]);

	await sessionTokens.verify("1.garbage");
	await sessionTokens.verify(
		await sealer.seal({
			purpose: "session",
			payload: { chain: "[]", expiresAtMilliseconds: "9999999" },
			timeToLive: durationOf(LIFE_TIME),
		}),
	);
	await sessionTokens.revoke({
		tenant: "acme",
		scope: "device",
		id: "laptop",
	});
	await sessionTokens.verify(issued.value);

	expect(summary(records)).toEqual([
		"session.issue:success:issued",
		"session.verify:refusal:invalid-seal",
		"session.verify:refusal:malformed-chain",
		"session.revoke:success:revoked",
		"session.verify:refusal:revoked",
	]);
	expect(records[0]).toMatchObject({
		tenant: "acme",
		subject: "alice",
		detail: { device: "laptop", session: session.id },
	});
	expect(records[3]).toMatchObject({
		tenant: "acme",
		detail: { scope: "device", id: "laptop" },
	});
	expect(records[4]).toMatchObject({
		tenant: "acme",
		subject: "alice",
		detail: { device: "laptop", scope: "device" },
	});
});

test("an expired session token is told apart from a forged one when the sealer reports too", async () => {
	const { records, sink } = createCollector();
	const sealer = createSealer({
		secrets: [{ version: 1, value: SECRET }],
		audit: sink,
	});
	const sessionTokens = createSessionTokens({
		sealer,
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		maximumLifeTimeMilliseconds: LIFE_TIME,
		audit: sink,
	});
	const issued = await sessionTokens.issue(await bornSession("alice"), {
		tenant: "acme",
		device: "laptop",
		timeToLive: durationOf(1_000),
		methods: ["test"],
	});

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	records.length = 0;
	vi.setSystemTime(2_500);
	await sessionTokens.verify(issued.value);
	await sessionTokens.verify(`${issued.value.slice(0, -2)}AA`);
	await sessionTokens.verify("9.abc");
	await sessionTokens.verify("garbage");

	expect(summary(records)).toEqual([
		"seal.unseal:refusal:expired",
		"session.verify:refusal:invalid-seal",
		"seal.unseal:refusal:undecryptable",
		"session.verify:refusal:invalid-seal",
		"seal.unseal:refusal:unknown-version",
		"session.verify:refusal:invalid-seal",
		"seal.unseal:refusal:malformed",
		"session.verify:refusal:invalid-seal",
	]);
});

test("a store that returns an expired record gets the reason expired", async () => {
	const { records, sink } = createCollector();
	const tokens = createTokens({
		store: {
			put: async () => undefined,
			take: async () => ({
				purpose: "email-link",
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
	const { sessionTokens } = createSessions(sink);
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

	const issued = await sessionTokens.issue(await bornSession("alice"), {
		tenant: "acme",
		device: "laptop",
		timeToLive: durationOf(LIFE_TIME),
		methods: ["test"],
	});

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	await sessionTokens.verify(`${issued.value}x`);

	const serialized = JSON.stringify(records);

	expect(serialized).not.toContain(link);
	expect(serialized).not.toContain(issued.value);
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
	const identities = createMemoryIdentityStore();
	const linkSpy = vi.fn(identities.linkIdentity);
	const store: IdentityStore = { ...identities, linkIdentity: linkSpy };

	await resolveIdentity(
		store,
		"acme",
		await proofOf({ ...validClaims, provider: "email" }),
	);

	await expect(
		resolveIdentity(store, "acme", await proofOf(validClaims), {
			audit: failingSink,
		}),
	).rejects.toThrow("the audit store is down");
	expect(linkSpy).not.toHaveBeenCalled();

	const tokenStore = createMemoryTokenStore({ maximumBytes: 1_000_000 });
	const tokens = createTokens({ store: tokenStore, audit: failingSink });

	await expect(
		tokens.issue({ purpose: "email-link", timeToLive: durationOf(1_000) }),
	).rejects.toThrow("the audit store is down");

	const { sessionTokens } = createSessions(failingSink);

	await expect(
		sessionTokens.issue(await bornSession("alice"), {
			tenant: "acme",
			device: "laptop",
			timeToLive: durationOf(LIFE_TIME),
			methods: ["test"],
		}),
	).rejects.toThrow("the audit store is down");
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
	const { sealer } = createSessions();
	const epochs = createMemoryEpochStore({ maximumBytes: 1_000_000 });
	const quiet = createSessionTokens({
		sealer,
		epochs,
		maximumLifeTimeMilliseconds: LIFE_TIME,
	});
	const loud = createSessionTokens({
		sealer,
		epochs,
		maximumLifeTimeMilliseconds: LIFE_TIME,
		audit: failingSink,
	});
	const issued = await quiet.issue(await bornSession("alice"), {
		tenant: "acme",
		device: "laptop",
		timeToLive: durationOf(LIFE_TIME),
		methods: ["test"],
	});

	if (!issued.ok) {
		throw new Error("the token must be issued");
	}

	await expect(
		loud.revoke({ tenant: "acme", scope: "tenant" }),
	).rejects.toThrow("the audit store is down");
	expect((await quiet.verify(issued.value)).ok).toBe(false);
});

test("a refusal still reaches the caller as a failure when the sink is down", async () => {
	const { sessionTokens } = createSessions(failingSink);

	await expect(sessionTokens.verify("1.garbage")).rejects.toThrow(
		"the audit store is down",
	);
});

test("the core reports exactly the documented events", () => {
	expect(Object.values(AUDIT_EVENTS).sort()).toEqual([
		"authorize.check",
		"delegation.grant",
		"identity.mutate",
		"identity.resolve",
		"meter.consume",
		"policy.evaluate",
		"proof.verify",
		"seal.unseal",
		"session.issue",
		"session.revoke",
		"session.verify",
		"signin.continue",
		"token.consume",
		"token.issue",
	]);
});
