import {
	createMemoryAccountStore,
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AgentReading,
	createAuth,
	createGrants,
	createRecordSeal,
	createRecords,
	type GrantStore,
	type SecretVersion,
	succeed,
} from "@vow-auth/core/internal";
import { durationOf, factorPluginOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const MINUTE = 60_000;
const IDLE = 10 * MINUTE;
const MAXIMUM = 60 * MINUTE;
const SECRETS: readonly SecretVersion[] = [
	{ version: 1, value: "client-secret-0123456789abcdefghijklm" },
];

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

/**
 * The engine, and the grants of the authorization server's clients on the
 * same grant store, as the server would hold them. The store can hand out an
 * agent changed past the engine.
 */
const createFixture = async () => {
	const base = createMemoryGrantStore();
	let tamper:
		| ((reading: AgentReading) => Promise<AgentReading | undefined>)
		| undefined;
	const store: GrantStore = {
		...base,
		getAgent: async (id) => {
			const reading = await base.getAgent(id);

			return tamper === undefined || reading === undefined
				? reading
				: tamper(reading);
		},
	};
	const auth = createAuth({
		accounts: createMemoryAccountStore(),
		grants: store,
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: SECRETS,
		factors: {
			email: factorPluginOf(async (response) =>
				succeed({
					provider: "email",
					externalId: String(Reflect.get(Object(response), "email")),
					email: String(Reflect.get(Object(response), "email")),
					emailVerified: true,
				}),
			),
		},
		maximumLifeTimeMilliseconds: MAXIMUM,
		sessionTimeToLiveMilliseconds: IDLE,
		registration: () => "allow",
		policy: () => "allow",
		audit: async () => undefined,
	});
	const grants = createGrants({
		store,
		records: createRecords(createRecordSeal({ secrets: SECRETS })),
		idleMilliseconds: IDLE,
		maximumMilliseconds: MAXIMUM,
	});

	await auth.tenants.create("acme");

	const signIn = async (email: string) => {
		const signed = await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email",
			response: { email },
		});

		if (!signed.ok) {
			throw new Error(`the sign in must pass: ${JSON.stringify(signed)}`);
		}

		return signed.value;
	};

	const grantClient = async (
		token: string,
		boundToSession: boolean,
		agent = "app",
	) => {
		const granted = await grants.grantClient(token, {
			tenant: "acme",
			agent,
			timeToLive: durationOf(30 * MINUTE),
			boundToSession,
		});

		if (!granted.ok) {
			throw new Error(`the grant must pass: ${JSON.stringify(granted)}`);
		}

		return granted.value;
	};

	return {
		auth,
		base,
		checkAgent: grants.checkAgent,
		grantClient,
		grants,
		signIn,
		tamperWith: (
			change: (reading: AgentReading) => Promise<AgentReading | undefined>,
		) => {
			tamper = change;
		},
	};
};

const refused = { ok: false, error: "invalid-session" };

test("A8: a client grant has no token of its own and is checked by its id as the person it acts for", async () => {
	const { base, checkAgent, grantClient, signIn } = await createFixture();
	const ivan = await signIn("ivan@example.com");
	const online = await grantClient(ivan.token, true);
	const offline = await grantClient(ivan.token, false);

	expect((await base.getAgent(online))?.agent.tokenHash).toBeUndefined();
	expect(await checkAgent(online)).toEqual({
		ok: true,
		value: {
			account: ivan.account,
			tenant: "acme",
			subject: ivan.subject,
			agent: "app",
			delegation: online,
			boundTo: { device: "laptop", session: ivan.session },
			delegatedAtMilliseconds: Date.now(),
		},
	});
	expect(await checkAgent(offline)).toMatchObject({
		ok: true,
		value: { subject: ivan.subject, boundTo: undefined },
	});
});

test("A8: a client grant bound to the session ends with it, an offline one outlives it, and both end with the client, the subject and the tenant", async () => {
	const fixture = await createFixture();
	const ivan = await fixture.signIn("ivan@example.com");
	const online = await fixture.grantClient(ivan.token, true);
	const offline = await fixture.grantClient(ivan.token, false);
	const other = await fixture.grantClient(ivan.token, false, "other-app");

	expect(await fixture.auth.sessions.end(ivan.token)).toBe(true);
	expect(await fixture.checkAgent(online)).toEqual(refused);
	expect((await fixture.checkAgent(offline)).ok).toBe(true);

	await fixture.auth.sessions.revoke({
		scope: "agent",
		tenant: "acme",
		id: "app",
	});

	expect(await fixture.checkAgent(offline)).toEqual(refused);
	expect((await fixture.checkAgent(other)).ok).toBe(true);

	await fixture.auth.memberships.suspend("acme", ivan.subject);

	expect(await fixture.checkAgent(other)).toEqual(refused);

	const again = await createFixture();
	const olga = await again.signIn("olga@example.com");
	const kept = await again.grantClient(olga.token, false);

	await again.auth.tenants.disable("acme");

	expect(await again.checkAgent(kept)).toEqual(refused);

	const third = await createFixture();
	const anna = await third.signIn("anna@example.com");
	const expiring = await third.grantClient(anna.token, false);

	vi.setSystemTime(Date.now() + 30 * MINUTE);

	expect(await third.checkAgent(expiring)).toEqual(refused);
});

test("A8: a client grant needs a live session entered into the tenant and a lifetime within the maximum", async () => {
	const { auth, grants, signIn } = await createFixture();
	const ivan = await signIn("ivan@example.com");
	const input = {
		tenant: "acme",
		agent: "app",
		timeToLive: durationOf(30 * MINUTE),
	};

	expect(
		await grants.grantClient(ivan.token, {
			...input,
			timeToLive: durationOf(MAXIMUM + 1),
		}),
	).toEqual({ ok: false, error: "invalid-request" });
	expect(
		await grants.grantClient(ivan.token, { ...input, tenant: "globex" }),
	).toEqual({ ok: false, error: "invalid-session" });

	await auth.sessions.end(ivan.token);

	expect(await grants.grantClient(ivan.token, input)).toEqual({
		ok: false,
		error: "invalid-session",
	});
});

test("A8: the check by id refuses an unknown id, the id of a session, an agent changed past the engine and another sealed agent than the one asked for", async () => {
	const { base, checkAgent, grantClient, signIn, tamperWith } =
		await createFixture();
	const ivan = await signIn("ivan@example.com");
	const olga = await signIn("olga@example.com");
	const ivans = await grantClient(ivan.token, false);
	const olgas = await grantClient(olga.token, false);

	expect(await checkAgent("grant-that-does-not-exist")).toEqual(refused);
	expect(await checkAgent(ivan.session)).toEqual(refused);
	expect(await checkAgent("")).toEqual(refused);

	tamperWith(async (reading) => ({
		...reading,
		agent: { ...reading.agent, subjectId: olga.subject },
	}));

	expect(await checkAgent(ivans)).toEqual(refused);

	tamperWith(async () => base.getAgent(olgas));

	expect(await checkAgent(ivans)).toEqual(refused);
	expect((await checkAgent(olgas)).ok).toBe(true);
});

test("A8: delegate still gives an agent a token of its own, and the check by id sees the same agent as the check by token", async () => {
	const { auth, checkAgent, signIn } = await createFixture();
	const ivan = await signIn("ivan@example.com");
	const delegation = await auth.agents.delegate(ivan.token, {
		tenant: "acme",
		agent: "search",
		timeToLive: durationOf(30 * MINUTE),
	});

	if (!delegation.ok) {
		throw new Error("the delegation must pass");
	}

	expect(delegation.value.token).toMatch(/^vag_/);
	expect(await checkAgent(delegation.value.delegation)).toEqual(
		await auth.agents.verify(delegation.value.token),
	);
});
