import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
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
import { createSealer } from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/store-contracts";
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
	const auth = createAuth({
		identities: createMemoryIdentityStore(),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: SECRET }],
		maximumLifeTimeMilliseconds: MAXIMUM_LIFE,
		sessionTimeToLiveMilliseconds: 30 * MINUTE,
		policy: () => "allow",
		audit: async (record) => {
			records.push(record);
		},
	});

	const signIn = async (address: string, device: string, tenant = "acme") => {
		const result = await auth.signIn({
			tenant,
			device,
			factor: emailFactor,
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

	return { auth, records, signIn, delegate, alive };
};

test("A8: a person's session token becomes an agent's token that names the person, the agent and the delegation", async () => {
	const { auth, signIn, delegate } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token, delegation } = await delegate(alice.token, "mcp-client-7");
	const verified = await auth.agents.verify(token);

	expect(verified).toEqual({
		ok: true,
		value: {
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

	expect(await auth.sessions.verify(token)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.agents.verify(alice.token)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(
		await auth.agents.delegate(token, {
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
	["the tenant", { tenant: "acme", scope: "tenant" }],
	["the person", { tenant: "acme", scope: "user", id: alice.subject }],
	["the agent", { tenant: "acme", scope: "agent", id: "mcp-client-7" }],
	[
		"the delegation",
		{ tenant: "acme", scope: "delegation", id: laptopDelegation },
	],
	["the device", { tenant: "acme", scope: "device", id: "laptop" }],
	["the session", { tenant: "acme", scope: "session", id: alice.session }],
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
		tenant: "acme",
		scope: "user",
		id: alice.subject,
	});

	expect((await auth.sessions.verify(alice.token)).ok).toBe(false);
	expect((await auth.sessions.verify(phone.token)).ok).toBe(false);
	expect(await alive(agent.token)).toBe(false);
});

test("A8: deleting the person ends their agents too", async () => {
	const { auth, signIn, delegate, alive } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const agent = await delegate(alice.token, "mcp-client-7");

	await auth.mutateIdentity("acme", alice.subject, { type: "delete" });

	expect(await alive(agent.token)).toBe(false);
});

test("A8: a revoked agent stays revoked for a delegation made after, and a revoked delegation does not touch a new one", async () => {
	const { auth, signIn, delegate, alive } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const first = await delegate(alice.token, "mcp-client-7");

	await auth.sessions.revoke({
		tenant: "acme",
		scope: "delegation",
		id: first.delegation,
	});

	const second = await delegate(alice.token, "mcp-client-7");

	expect(await alive(first.token)).toBe(false);
	expect(await alive(second.token)).toBe(true);
});

test("A8: delegating needs a living session of the person", async () => {
	const { auth, signIn, records } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const input = { agent: "mcp-client-7", timeToLive: durationOf(MINUTE) };

	expect(await auth.agents.delegate("garbage", input)).toEqual({
		ok: false,
		error: "invalid-session",
	});

	await auth.sessions.revoke({
		tenant: "acme",
		scope: "session",
		id: alice.session,
	});

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
		{ agent: "", timeToLive: durationOf(MINUTE) },
		{ agent: "mcp-client-7", timeToLive: durationOf(MAXIMUM_LIFE + 1) },
		{ agent: "mcp-client-7", timeToLive: { milliseconds: MINUTE } },
		{ agent: 7, timeToLive: durationOf(MINUTE) },
		{ timeToLive: durationOf(MINUTE) },
		{ agent: "mcp-client-7" },
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

test("A8: an agent chain of an unknown shape is rejected", async () => {
	const { auth } = createFixture();
	const sealer = createSealer({ secrets: [{ version: 1, value: SECRET }] });
	const link = (scope: string, id: string) => ({
		scope,
		id,
		stamp: Date.now(),
	});
	const shapes: readonly (readonly [string, readonly unknown[]])[] = [
		[
			"four links, the known shape",
			[
				link("tenant", "acme"),
				link("user", "alice"),
				link("agent", "a"),
				link("delegation", "d"),
			],
		],
		[
			"a session chain",
			[
				link("tenant", "acme"),
				link("user", "alice"),
				link("device", "laptop"),
				link("session", "s"),
			],
		],
		[
			"five links",
			[
				link("tenant", "acme"),
				link("user", "alice"),
				link("device", "laptop"),
				link("agent", "a"),
				link("delegation", "d"),
			],
		],
		[
			"the agent before the person",
			[
				link("tenant", "acme"),
				link("agent", "a"),
				link("user", "alice"),
				link("delegation", "d"),
			],
		],
		[
			"a delegation without an agent",
			[link("tenant", "acme"), link("user", "alice"), link("delegation", "d")],
		],
	];
	const accepted: string[] = [];

	for (const [name, chain] of shapes) {
		const token = await sealer.seal({
			purpose: "agent",
			payload: {
				chain: JSON.stringify(chain),
				expiresAtMilliseconds: String(Date.now() + MINUTE),
				delegatedAtMilliseconds: String(Date.now()),
			},
			timeToLive: durationOf(MINUTE),
		});

		if ((await auth.agents.verify(token)).ok) {
			accepted.push(name);
		}
	}

	expect(accepted).toEqual(["four links, the known shape"]);
});

test("A8: the audit records a delegation, and says which level of the chain was revoked", async () => {
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
		tenant: "acme",
		scope: "agent",
		id: "mcp-client-7",
	});
	records.length = 0;
	await auth.agents.verify(token);

	expect(records).toEqual([
		expect.objectContaining({
			event: "session.verify",
			outcome: "refusal",
			reason: "revoked",
			detail: { agent: "mcp-client-7", delegation, scope: "agent" },
		}),
	]);
});

test("A8: the audit of a refused agent carries no secret", async () => {
	const { auth, signIn, delegate, records } = createFixture();
	const alice = await signIn("alice@example.com", "laptop");
	const { token } = await delegate(alice.token, "mcp-client-7");

	await auth.sessions.revoke({ tenant: "acme", scope: "tenant" });
	await auth.agents.verify(token);

	expect(JSON.stringify(records)).not.toContain(token);
	expect(JSON.stringify(records)).not.toContain(alice.token);
});
