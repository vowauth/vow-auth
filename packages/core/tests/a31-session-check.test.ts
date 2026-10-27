import {
	createMemoryAccountStore,
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	createAuth,
	createGrants,
	createRecordSeal,
	createRecords,
	type GrantStore,
	type SecretVersion,
	type SessionReading,
	succeed,
} from "@vow-auth/core/internal";
import { durationOf, factorPluginOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const MINUTE = 60_000;
const IDLE = 10 * MINUTE;
const MAXIMUM = 60 * MINUTE;
const SECRETS: readonly SecretVersion[] = [
	{ version: 1, value: "check-secret-0123456789abcdefghijklmn" },
];

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const later = (milliseconds: number) =>
	vi.setSystemTime(Date.now() + milliseconds);

/**
 * The engine, and a check of sessions by id on its grant store, as the
 * authorization server would hold it. The store counts the extensions of the
 * idle end, and can hand out a reading changed past the engine.
 */
const createFixture = async () => {
	const base = createMemoryGrantStore();
	const extended: string[] = [];
	let tamper:
		| ((reading: SessionReading) => Promise<SessionReading | undefined>)
		| undefined;
	const store: GrantStore = {
		...base,
		extendSession: async (id, idle) => {
			extended.push(id);

			return base.extendSession(id, idle);
		},
		getSession: async (id, tenant) => {
			const reading = await base.getSession(id, tenant);

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
	await auth.tenants.create("globex");

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

	return {
		auth,
		base,
		check: grants.check,
		extended,
		signed: await signIn("ivan@example.com"),
		signIn,
		tamperWith: (
			change: (reading: SessionReading) => Promise<SessionReading | undefined>,
		) => {
			tamper = change;
		},
	};
};

const refused = { ok: false, error: "invalid-session" };

test("A31: a live session checked by its id is the person verify sees, and the check is not a use, so the idle end stays", async () => {
	const { auth, check, extended, signed } = await createFixture();
	const verified = await auth.sessions.verify(signed.token, "acme");
	const checked = await check(signed.session, "acme");

	expect(checked).toEqual(verified);

	later(IDLE * 0.6);
	extended.length = 0;

	expect((await check(signed.session, "acme")).ok).toBe(true);
	expect(extended).toEqual([]);

	later(IDLE * 0.5);

	expect(await check(signed.session, "acme")).toEqual(refused);
});

test("A31: a session revoked, ended, or taken out of the tenant fails the check by id, and so do a tenant it never entered, an unknown id and the id of another grant", async () => {
	const { auth, check, signed } = await createFixture();
	const delegation = await auth.agents.delegate(signed.token, {
		tenant: "acme",
		agent: "search",
		timeToLive: durationOf(MINUTE),
	});

	if (!delegation.ok) {
		throw new Error("the delegation must pass");
	}

	expect(await check(signed.session, "globex")).toEqual(refused);
	expect(await check("grant-that-does-not-exist", "acme")).toEqual(refused);
	expect(await check(delegation.value.delegation, "acme")).toEqual(refused);
	expect(await check(signed.session, "")).toEqual(refused);

	await auth.memberships.suspend("acme", signed.subject);

	expect(await check(signed.session, "acme")).toEqual(refused);

	const again = await createFixture();

	expect(await again.auth.sessions.end(again.signed.token)).toBe(true);
	expect(await again.check(again.signed.session, "acme")).toEqual(refused);

	const third = await createFixture();

	await third.auth.sessions.revoke({
		scope: "session",
		id: third.signed.session,
	});

	expect(await third.check(third.signed.session, "acme")).toEqual(refused);
});

test("A31: a session read back changed past the engine, or another sealed session than the one asked for, fails the check by id", async () => {
	const { base, check, signed, signIn, tamperWith } = await createFixture();
	const olga = await signIn("olga@example.com");

	tamperWith(async (reading) => ({
		...reading,
		entry:
			reading.entry === undefined
				? undefined
				: { ...reading.entry, subjectId: olga.subject },
	}));

	expect(await check(signed.session, "acme")).toEqual(refused);

	tamperWith(async () => base.getSession(olga.session, "acme"));

	expect(await check(signed.session, "acme")).toEqual(refused);
	expect((await check(olga.session, "acme")).ok).toBe(true);
});
