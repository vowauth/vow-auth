import {
	createMemoryAccountStore,
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AuditRecord,
	createAuth,
	type Factor,
	fail,
	type RevocationLevel,
	succeed,
} from "@vow-auth/core";
import { createRecordSeal, createRecords } from "@vow-auth/core/internal";
import { durationOf, factorPluginOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const MINUTE = 60_000;
const MAXIMUM_LIFE = 60 * MINUTE;
const SECRET = "agents-secret-0123456789abcdefghijklmn";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const emailFactor: Factor = {
	id: "email",
	strength: "possession",
	verify: async (response) => {
		const address =
			typeof response === "object" && response !== null
				? Reflect.get(response, "email")
				: undefined;

		return typeof address === "string"
			? succeed({
					provider: "email",
					externalId: address,
					email: address,
					emailVerified: true,
				})
			: fail("invalid-proof");
	},
};

const createFixture = () => {
	const records: AuditRecord[] = [];
	const grantStore = createMemoryGrantStore();
	const auth = createAuth({
		factors: {
			email: factorPluginOf(emailFactor.verify, { providers: ["email"] }),
		},
		accounts: createMemoryAccountStore(),
		grants: grantStore,
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: SECRET }],
		maximumLifeTimeMilliseconds: MAXIMUM_LIFE,
		sessionTimeToLiveMilliseconds: 30 * MINUTE,
		registration: () => "allow",
		policy: () => "allow",
		audit: async (record) => {
			records.push(record);
		},
	});

	const signIn = async (address: string, device: string, tenant = "acme") => {
		await auth.tenants.create(tenant);

		const result = await auth.signIn({
			tenant,
			device,
			factor: "email",
			response: { email: address },
		});

		if (!result.ok) {
			throw new Error("the sign in must pass");
		}

		return result.value;
	};

	const delegate = async (
		sessionToken: string,
		agent: string,
		boundToSession = false,
	) => {
		const result = await auth.agents.delegate(sessionToken, {
			tenant: "acme",
			agent,
			timeToLive: durationOf(30 * MINUTE),
			boundToSession,
		});

		if (!result.ok) {
			throw new Error("the delegation must pass");
		}

		return result.value;
	};

	const alive = async (token: string) => (await auth.agents.verify(token)).ok;

	return { auth, grantStore, records, signIn, delegate, alive };
};

test("A8: a person's session token becomes an agent's token that names the person, the agent and the delegation", async () => {
	const { auth, signIn, delegate } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token, delegation } = await delegate(alice.token, "mcp-client-7");
	const verified = await auth.agents.verify(token);

	expect(verified).toEqual({
		ok: true,
		value: {
			account: alice.account,
			tenant: "acme",
			subject: alice.subject,
			agent: "mcp-client-7",
			delegation,
			boundTo: undefined,
			delegatedAtMilliseconds: Date.now(),
		},
	});
});

test("A8: an agent token is never a session and a session token is never an agent", async () => {
	const { auth, signIn, delegate } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token } = await delegate(alice.token, "mcp-client-7");

	expect(await auth.sessions.verify(token, "acme")).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.agents.verify(alice.token)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(
		await auth.agents.delegate(token, {
			tenant: "acme",
			agent: "second-hop",
			timeToLive: durationOf(MINUTE),
		}),
	).toEqual({ ok: false, error: "invalid-session" });
});

test("A8: a delegation tied to the session names the device and session it came from", async () => {
	const { auth, signIn, delegate } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token } = await delegate(alice.token, "mcp-client-7", true);
	const verified = await auth.agents.verify(token);

	expect(verified.ok && verified.value.boundTo).toEqual({
		device: "laptop",
		session: alice.session,
	});
});

const levelsOf = (
	alice: { subject: string; session: string },
	laptopDelegation: string,
): readonly (readonly [string, RevocationLevel])[] => [
	["the tenant", { scope: "tenant", tenant: "acme" }],
	["the person", { scope: "subject", tenant: "acme", id: alice.subject }],
	["the agent", { scope: "agent", tenant: "acme", id: "mcp-client-7" }],
	["the delegation", { scope: "delegation", id: laptopDelegation }],
	["the device", { scope: "device", id: "laptop" }],
	["the session", { scope: "session", id: alice.session }],
];

test("A8: revoking a level kills exactly the agents below it", async () => {
	const expected: Record<string, readonly string[]> = {
		"the tenant": ["unbound", "bound", "other-agent", "bob"],
		"the person": ["unbound", "bound", "other-agent"],
		"the agent": ["unbound", "bound", "bob"],
		"the delegation": ["unbound"],
		"the device": ["bound"],
		"the session": ["bound"],
	};

	for (const name of Object.keys(expected)) {
		const { auth, signIn, delegate, alive } = createFixture();
		const alice = await signIn("alice@example.com", "laptop");
		const bob = await signIn("bob@example.com", "laptop");
		const unbound = await delegate(alice.token, "mcp-client-7");
		const bound = await delegate(alice.token, "mcp-client-7", true);
		const otherAgent = await delegate(alice.token, "another-agent");
		const bobsAgent = await delegate(bob.token, "mcp-client-7");
		const tokens: Record<string, string> = {
			unbound: unbound.token,
			bound: bound.token,
			"other-agent": otherAgent.token,
			bob: bobsAgent.token,
		};
		const level = levelsOf(alice, unbound.delegation).find(
			([label]) => label === name,
		)?.[1];

		if (level === undefined) {
			throw new Error(`no level named ${name}`);
		}

		await auth.sessions.revoke(level);

		const dead: string[] = [];

		for (const [label, token] of Object.entries(tokens)) {
			if (!(await alive(token))) {
				dead.push(label);
			}
		}

		expect(dead.sort(), `revoking ${name}`).toEqual(
			[...(expected[name] ?? [])].sort(),
		);
	}
});

test("A8: revoking the parent also ends the person's own sessions, so the whole chain goes", async () => {
	const { auth, signIn, delegate, alive } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const phone = await signIn("alice@example.com", "phone");
	const agent = await delegate(alice.token, "mcp-client-7", true);

	await auth.sessions.revoke({
		scope: "subject",
		tenant: "acme",
		id: alice.subject,
	});

	expect((await auth.sessions.verify(alice.token, "acme")).ok).toBe(false);
	expect((await auth.sessions.verify(phone.token, "acme")).ok).toBe(false);
	expect(await alive(agent.token)).toBe(false);
});

test("A8: deleting the person ends their agents too", async () => {
	const { auth, signIn, delegate, alive } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const agent = await delegate(alice.token, "mcp-client-7");

	await auth.accounts.delete(alice.account);

	expect(await alive(agent.token)).toBe(false);
});

test("A8: a revoked agent stays revoked for a delegation made after, and a revoked delegation does not touch a new one", async () => {
	const { auth, signIn, delegate, alive } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const first = await delegate(alice.token, "mcp-client-7");

	await auth.sessions.revoke({ scope: "delegation", id: first.delegation });

	const second = await delegate(alice.token, "mcp-client-7");

	expect(await alive(first.token)).toBe(false);
	expect(await alive(second.token)).toBe(true);
});

test("A8: delegating needs a living session of the person", async () => {
	const { auth, signIn, records } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const input = {
		tenant: "acme",
		agent: "mcp-client-7",
		timeToLive: durationOf(MINUTE),
	};

	expect(await auth.agents.delegate("garbage", input)).toEqual({
		ok: false,
		error: "invalid-session",
	});

	await auth.sessions.revoke({ scope: "session", id: alice.session });

	expect(await auth.agents.delegate(alice.token, input)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(
		records.filter((record) => record.event === "delegation.grant"),
	).toEqual([]);
});

test("A8: a delegation with a name or a life time the core cannot use is refused", async () => {
	const { auth, signIn } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");

	const inputs: readonly unknown[] = [
		{ tenant: "acme", agent: "", timeToLive: durationOf(MINUTE) },
		{
			tenant: "acme",
			agent: "mcp-client-7",
			timeToLive: durationOf(MAXIMUM_LIFE + 1),
		},
		{
			tenant: "acme",
			agent: "mcp-client-7",
			timeToLive: { milliseconds: MINUTE },
		},
		{ tenant: "acme", agent: 7, timeToLive: durationOf(MINUTE) },
		{ tenant: "acme", timeToLive: durationOf(MINUTE) },
		{ tenant: "acme", agent: "mcp-client-7" },
		{ agent: "mcp-client-7", timeToLive: durationOf(MINUTE) },
	];

	for (const input of inputs) {
		expect(
			// @ts-expect-error input of an unknown shape
			await auth.agents.delegate(alice.token, input),
		).toEqual({ ok: false, error: "invalid-request" });
	}
});

test("A8: an agent token expires by the delegation's life time", async () => {
	const { auth, signIn } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const delegated = await auth.agents.delegate(alice.token, {
		tenant: "acme",
		agent: "mcp-client-7",
		timeToLive: durationOf(10 * MINUTE),
	});

	if (!delegated.ok) {
		throw new Error("the delegation must pass");
	}

	vi.setSystemTime(Date.now() + 10 * MINUTE - 1);
	expect((await auth.agents.verify(delegated.value.token)).ok).toBe(true);

	vi.setSystemTime(Date.now() + 2);
	expect((await auth.agents.verify(delegated.value.token)).ok).toBe(false);
});

test("A8: an agent grant written past the engine, or a grant of another kind, opens nothing", async () => {
	const { auth, grantStore } = createFixture();
	const sealed = createRecords(
		createRecordSeal({ secrets: [{ version: 1, value: SECRET }] }),
	);
	const hashOf = async (text: string) =>
		Array.from(
			new Uint8Array(
				await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
			),
			(byte) => byte.toString(16).padStart(2, "0"),
		).join("");
	const grantFor = async (token: string, kind: "agent" | "session") => ({
		id: crypto.randomUUID(),
		kind,
		tokenHash: await hashOf(token),
		accountId: "acc_mallory",
		tenant: "acme",
		subjectId: "sub_mallory",
		device: undefined,
		agent: "bot",
		parentId: undefined,
		sessionId: undefined,
		proofs: undefined,
		authenticatedAtMilliseconds: Date.now(),
		expiresAtMilliseconds: Date.now() + MINUTE,
		idleExpiresAtMilliseconds: undefined,
		revoked: false,
	});
	const forged = `vag_${"a".repeat(64)}`;
	const otherKind = `vag_${"b".repeat(64)}`;

	await grantStore.createGrant({
		...(await grantFor(forged, "agent")),
		seal: "1.AAAA",
	});
	await grantStore.createGrant(
		await sealed.grant(await grantFor(otherKind, "session")),
	);

	expect(await auth.agents.verify(forged)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.agents.verify(otherKind)).toEqual({
		ok: false,
		error: "invalid-session",
	});
});

test("A8: the audit records a delegation, and a refused agent with the reason", async () => {
	const { auth, signIn, delegate, records } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token, delegation } = await delegate(alice.token, "mcp-client-7");

	expect(
		records.find((record) => record.event === "delegation.grant"),
	).toMatchObject({
		event: "delegation.grant",
		outcome: "success",
		reason: "issued",
		tenant: "acme",
		subject: alice.subject,
		detail: { agent: "mcp-client-7", delegation, bound: "false" },
	});

	await auth.sessions.revoke({
		scope: "agent",
		tenant: "acme",
		id: "mcp-client-7",
	});
	records.length = 0;
	await auth.agents.verify(token);

	expect(records).toEqual([
		expect.objectContaining({
			event: "session.verify",
			outcome: "refusal",
			reason: "revoked",
			detail: { agent: "mcp-client-7", delegation, scope: "delegation" },
		}),
	]);
});

test("A8: the audit of a refused agent carries no secret", async () => {
	const { auth, signIn, delegate, records } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token } = await delegate(alice.token, "mcp-client-7");

	await auth.sessions.revoke({ scope: "tenant", tenant: "acme" });
	await auth.agents.verify(token);

	expect(JSON.stringify(records)).not.toContain(token);
	expect(JSON.stringify(records)).not.toContain(alice.token);
});
