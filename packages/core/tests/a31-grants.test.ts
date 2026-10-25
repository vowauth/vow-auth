import {
	createMemoryAccountStore,
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	createAuth,
	fail,
	type GrantStore,
	requireFactor,
	type SignInPolicyInput,
	succeed,
} from "@vow-auth/core";
import { durationOf, factorPluginOf } from "@vow-auth/test-support";
import fastCheck from "fast-check";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const MINUTE = 60_000;
const IDLE = 10 * MINUTE;
const MAXIMUM = 60 * MINUTE;
const GOOD_CODE = "424242";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const textOf = (response: unknown, key: string): string =>
	typeof response === "object" && response !== null
		? String(Reflect.get(response, key) ?? "")
		: "";

const sha256 = async (text: string): Promise<string> =>
	Array.from(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
		),
		(byte) => byte.toString(16).padStart(2, "0"),
	).join("");

/** A grant store whose clock is its own, and that counts how often a session is extended. */
const clockedStore = (clock: () => number) => {
	const store = createMemoryGrantStore();
	const extended: number[] = [];
	const wrapped: GrantStore = {
		...store,
		now: async () => clock(),
		findSession: async (hash, tenant) => {
			const reading = await store.findSession(hash, tenant);

			return reading === undefined ? undefined : { ...reading, now: clock() };
		},
		findAgent: async (hash) => {
			const reading = await store.findAgent(hash);

			return reading === undefined ? undefined : { ...reading, now: clock() };
		},
		extendSession: async (id, idle) => {
			extended.push(idle);

			return store.extendSession(id, idle);
		},
	};

	return { store: wrapped, extended };
};

const createFixture = (
	options: {
		readonly policy?: (input: SignInPolicyInput) => unknown;
		readonly clock?: () => number;
	} = {},
) => {
	const grants = clockedStore(options.clock ?? Date.now);
	const auth = createAuth({
		accounts: createMemoryAccountStore(),
		grants: grants.store,
		factors: {
			email: factorPluginOf(
				async (response) =>
					succeed({
						provider: "email",
						externalId: textOf(response, "email"),
						email: textOf(response, "email"),
						emailVerified: true,
					}),
				{ providers: ["email"] },
			),
			code: factorPluginOf(
				async (response, context) => {
					const first = context.proofs[0];

					return textOf(response, "code") === GOOD_CODE && first
						? succeed({
								provider: first.claims.provider,
								externalId: first.claims.externalId,
								emailVerified: first.claims.emailVerified,
								...(first.claims.email === undefined
									? {}
									: { email: first.claims.email.address }),
							})
						: fail("invalid-proof");
				},
				{ providers: ["code"] },
			),
		},
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: "grants-secret-0123456789abcdefghijkl" }],
		maximumLifeTimeMilliseconds: MAXIMUM,
		sessionTimeToLiveMilliseconds: IDLE,
		stepUpTimeToLiveMilliseconds: 5 * MINUTE,
		registration: () => "allow",
		policy: options.policy ?? (() => "allow"),
		audit: async () => undefined,
	});
	const ready = Promise.all(
		["acme", "globex"].map((tenant) => auth.tenants.create(tenant)),
	);

	const signedIn = async (
		email: string,
		tenant = "acme",
		device = "laptop",
	) => {
		await ready;

		const result = await auth.signIn({
			tenant,
			device,
			factor: "email",
			response: { email },
		});

		if (!result.ok) {
			throw new Error(`the sign in must pass: ${JSON.stringify(result)}`);
		}

		return result.value;
	};

	const alive = async (token: string, tenant = "acme") =>
		(await auth.sessions.verify(token, tenant)).ok;

	return {
		auth,
		extended: grants.extended,
		store: grants.store,
		alive,
		signedIn,
	};
};

test("the store keeps only the hash of a session token, and every sign in gets a token of its own", async () => {
	const { store, signedIn } = createFixture();
	const first = await signedIn("ivan@example.com");
	const second = await signedIn("ivan@example.com");
	const reading = await store.findSession(await sha256(first.token), "acme");

	expect(first.token).toMatch(/^vas_[0-9a-f]{64}$/);
	expect(second.token).not.toBe(first.token);
	expect(second.session).not.toBe(first.session);
	expect(second.account).toBe(first.account);
	expect(reading?.session.id).toBe(first.session);
	expect(JSON.stringify(reading)).not.toContain(first.token);
});

test("a session opens the tenants it entered and no other, and says whose it is", async () => {
	const { auth, alive, signedIn } = createFixture();
	const ivan = await signedIn("ivan@example.com");

	expect(await auth.sessions.verify(ivan.token, "acme")).toMatchObject({
		ok: true,
		value: {
			account: ivan.account,
			tenant: "acme",
			subject: ivan.subject,
			device: "laptop",
			session: ivan.session,
			methods: ["email"],
		},
	});
	expect(await alive(ivan.token, "globex")).toBe(false);
	expect(await alive(ivan.token, "nowhere")).toBe(false);
});

test("a session enters another tenant without a new sign in, with a subject of its own there", async () => {
	const { auth, alive, signedIn } = createFixture();
	const ivan = await signedIn("ivan@example.com");
	const entered = await auth.sessions.enter(ivan.token, "globex");

	expect(entered).toMatchObject({
		ok: true,
		value: {
			tenant: "globex",
			account: ivan.account,
			membership: "created",
		},
	});
	expect(entered.ok && entered.value.subject).not.toBe(ivan.subject);
	expect(await alive(ivan.token, "globex")).toBe(true);
	expect(await alive(ivan.token, "acme")).toBe(true);
	expect(await auth.sessions.enter(ivan.token, "globex")).toMatchObject({
		ok: true,
		value: { membership: "existing" },
	});
	expect(await auth.sessions.enter(ivan.token, "nowhere")).toEqual({
		ok: false,
		error: "no-tenant",
	});
	expect(await auth.sessions.enter("garbage", "globex")).toEqual({
		ok: false,
		error: "invalid-session",
	});
});

test("entering a tenant that wants one more factor gives a new session, and the old one stays as it was", async () => {
	const { auth, alive, signedIn } = createFixture({
		policy: (input) =>
			input.tenant === "globex" &&
			!input.proofs.some((proof) => proof.factor === "code")
				? requireFactor("code")
				: "allow",
	});
	const ivan = await signedIn("ivan@example.com");
	const asked = await auth.sessions.enter(ivan.token, "globex");
	const error = asked.ok ? undefined : asked.error;

	if (typeof error !== "object" || error === undefined) {
		throw new Error("the tenant must ask for a factor");
	}

	expect(error).toMatchObject({ code: "step-up-required", factor: "code" });
	expect(await alive(ivan.token, "globex")).toBe(false);

	const stronger = await auth.signIn({
		tenant: "globex",
		device: "laptop",
		factor: "code",
		response: { code: GOOD_CODE },
		continuation: error.continuation,
	});

	if (!stronger.ok) {
		throw new Error("the second factor must sign in");
	}

	expect(stronger.value.token).not.toBe(ivan.token);
	expect(stronger.value.account).toBe(ivan.account);
	expect(
		await auth.sessions.verify(stronger.value.token, "globex"),
	).toMatchObject({ ok: true, value: { methods: ["email", "code"] } });
	expect(await alive(ivan.token, "globex")).toBe(false);
	expect(await alive(ivan.token, "acme")).toBe(true);
	expect((await auth.sessions.enter(stronger.value.token, "acme")).ok).toBe(
		true,
	);
});

test("a suspended membership cannot be entered, and the tenant's own session of it is gone", async () => {
	const { auth, alive, signedIn } = createFixture();
	const ivan = await signedIn("ivan@example.com");
	const inGlobex = await signedIn("ivan@example.com", "globex");

	await auth.memberships.suspend("globex", inGlobex.subject);

	expect(await alive(inGlobex.token, "globex")).toBe(false);
	expect(await auth.sessions.enter(ivan.token, "globex")).toEqual({
		ok: false,
		error: "suspended",
	});
	expect(await alive(ivan.token, "acme")).toBe(true);
});

test("a session ends after the idle time unless it is used, and at its end whatever happens", async () => {
	const { alive, extended, signedIn } = createFixture();
	const start = Date.now();
	const ivan = await signedIn("ivan@example.com");

	vi.setSystemTime(start + 4 * MINUTE);
	expect(await alive(ivan.token)).toBe(true);
	expect(extended).toEqual([]);

	vi.setSystemTime(start + 6 * MINUTE);
	expect(await alive(ivan.token)).toBe(true);
	expect(extended).toEqual([start + 16 * MINUTE]);

	vi.setSystemTime(start + 7 * MINUTE);
	expect(await alive(ivan.token)).toBe(true);
	expect(extended).toHaveLength(1);

	vi.setSystemTime(start + 16 * MINUTE);
	expect(await alive(ivan.token)).toBe(false);

	const busy = await signedIn("busy@example.com");
	const busyStart = Date.now();

	for (let minute = 4; minute < 60; minute += 4) {
		vi.setSystemTime(busyStart + minute * MINUTE);
		expect(await alive(busy.token), `minute ${minute}`).toBe(true);
	}

	vi.setSystemTime(busyStart + MAXIMUM);
	expect(await alive(busy.token)).toBe(false);
});

test("a session ends by the store's clock, whatever the clock of the server says", async () => {
	let storeTime = 5_000_000;
	const { alive, signedIn } = createFixture({ clock: () => storeTime });
	const ivan = await signedIn("ivan@example.com");

	vi.setSystemTime(Date.now() + 100 * MAXIMUM);
	expect(await alive(ivan.token)).toBe(true);

	vi.setSystemTime(0);
	storeTime += IDLE;
	expect(await alive(ivan.token)).toBe(false);
});

test("signing out ends this session, every session of the device, or every session of the account, and agents of their own stay", async () => {
	const { auth, alive, signedIn } = createFixture();
	const laptop = await signedIn("ivan@example.com", "acme", "laptop");
	const second = await signedIn("ivan@example.com", "acme", "laptop");
	const phone = await signedIn("ivan@example.com", "acme", "phone");
	const tablet = await signedIn("ivan@example.com", "acme", "tablet");
	const agent = await auth.agents.delegate(tablet.token, {
		tenant: "acme",
		agent: "claude",
		timeToLive: durationOf(MAXIMUM),
	});

	if (!agent.ok) {
		throw new Error("the delegation must pass");
	}

	expect(await auth.sessions.end(laptop.token)).toBe(true);
	expect(await alive(laptop.token)).toBe(false);
	expect(await alive(second.token)).toBe(true);

	expect(await auth.sessions.end(second.token, "device")).toBe(true);
	expect(await alive(second.token)).toBe(false);
	expect(await alive(phone.token)).toBe(true);

	expect(await auth.sessions.end(phone.token, "account")).toBe(true);
	expect(await alive(phone.token)).toBe(false);
	expect(await alive(tablet.token)).toBe(false);
	expect(await auth.sessions.end(phone.token)).toBe(false);
	expect((await auth.agents.verify(agent.value.token)).ok).toBe(true);
});

test("anything but a session token is refused with one error", async () => {
	const { auth } = createFixture();

	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.string(), async (guess) => {
			expect(await auth.sessions.verify(guess, "acme")).toEqual({
				ok: false,
				error: "invalid-session",
			});
		}),
	);
	expect(await auth.sessions.verify(`vas_${"0".repeat(64)}`, "acme")).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.sessions.verify(`vag_${"0".repeat(64)}`, "acme")).toEqual({
		ok: false,
		error: "invalid-session",
	});
});
