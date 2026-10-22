import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryOutboxStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	createAuth,
	createEmit,
	type Factor,
	fail,
	type IdentityStore,
	succeed,
} from "@vow-auth/core";
import { durationOf } from "@vow-auth/test-support";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

const MINUTE = 60_000;

const spyOn = <Store extends object>(store: Store, calls: string[]): Store => {
	const spied = { ...store };

	for (const [name, member] of Object.entries(store)) {
		if (typeof member === "function") {
			Reflect.set(spied, name, (...args: unknown[]) => {
				calls.push(name);

				return member.apply(store, args);
			});
		}
	}

	return spied;
};

const claimsFactor = (claims: unknown): Factor => ({
	id: "claims",
	strength: "possession",
	verify: async () => succeed(claims),
});

const goodClaims = {
	provider: "idp",
	externalId: "alice",
	emailVerified: false,
};

const createFixture = () => {
	const calls: string[] = [];
	const identities: IdentityStore = spyOn(createMemoryIdentityStore(), calls);
	const auth = createAuth({
		identities,
		epochs: spyOn(createMemoryEpochStore({ maximumBytes: 1_000_000 }), calls),
		tokenStore: spyOn(
			createMemoryTokenStore({ maximumBytes: 1_000_000 }),
			calls,
		),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: "storable-secret-0123456789abcdefghijk" }],
		maximumLifeTimeMilliseconds: 60 * MINUTE,
		sessionTimeToLiveMilliseconds: 30 * MINUTE,
		policy: () => "allow",
		audit: async () => undefined,
	});

	return { auth, calls };
};

const cannotBeStored = fastCheck
	.tuple(
		fastCheck.string({ maxLength: 8 }),
		fastCheck.constantFrom(
			"\u0000",
			"\u0001",
			"\t",
			"\n",
			"\u001f",
			"\u007f",
			"\u0085",
			"\u009f",
			"\ud800",
			"\udbff",
			"\udc00",
			"\udfff",
		),
		fastCheck.string({ maxLength: 8 }),
	)
	.map(([before, bad, after]) => `${before}${bad}${after}`);

test("a name with a control character or a lone surrogate stops at the border, before any store", async () => {
	await fastCheck.assert(
		fastCheck.asyncProperty(cannotBeStored, async (bad) => {
			const { auth, calls } = createFixture();
			const request = {
				tenant: "acme",
				device: "laptop",
				factor: claimsFactor(goodClaims),
				response: {},
			};

			expect(await auth.signIn({ ...request, tenant: bad })).toEqual({
				ok: false,
				error: "invalid-request",
			});
			expect(await auth.signIn({ ...request, device: bad })).toEqual({
				ok: false,
				error: "invalid-request",
			});
			expect(await auth.signIn({ ...request, continuation: bad })).toEqual({
				ok: false,
				error: "invalid-request",
			});
			expect(
				await auth.signIn({
					...request,
					factor: claimsFactor({ ...goodClaims, provider: bad }),
				}),
			).toEqual({ ok: false, error: "invalid-proof" });
			expect(
				await auth.signIn({
					...request,
					factor: claimsFactor({ ...goodClaims, externalId: bad }),
				}),
			).toEqual({ ok: false, error: "invalid-proof" });
			expect(
				await auth.mutateIdentity(bad, "subject", { type: "delete" }),
			).toEqual({
				ok: false,
				error: "invalid-request",
			});
			expect(
				await auth.mutateIdentity("acme", bad, { type: "delete" }),
			).toEqual({
				ok: false,
				error: "invalid-request",
			});
			expect(calls).toEqual([]);
		}),
		{ numRuns: 200 },
	);
});

test("an agent whose name cannot be stored is refused before anything is written", async () => {
	const { auth, calls } = createFixture();
	const signedIn = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: claimsFactor(goodClaims),
		response: {},
	});

	if (!signedIn.ok) {
		throw new Error("the sign in must pass");
	}

	calls.length = 0;

	await fastCheck.assert(
		fastCheck.asyncProperty(cannotBeStored, async (bad) => {
			expect(
				await auth.agents.delegate(signedIn.value.token, {
					agent: bad,
					timeToLive: durationOf(MINUTE),
				}),
			).toEqual({ ok: false, error: "invalid-request" });
		}),
		{ numRuns: 100 },
	);
	expect(calls.filter((name) => name === "revoke")).toEqual([]);
});

test("an event type that cannot be stored is refused, while a payload may hold any text", async () => {
	const store = createMemoryOutboxStore();
	const emit = createEmit(store);

	await fastCheck.assert(
		fastCheck.asyncProperty(cannotBeStored, async (bad) => {
			expect(await emit({ type: bad, payload: {} })).toEqual({
				ok: false,
				error: "invalid-event",
			});
		}),
		{ numRuns: 100 },
	);
	expect(store.pending()).toBe(0);
	expect(
		(
			await emit({
				type: "mail",
				payload: { body: "line one\nline two\u0000" },
			})
		).ok,
	).toBe(true);
});

test("names that people really use are accepted", async () => {
	for (const name of [
		"Ivan's phone",
		"👩‍💻 laptop",
		"ноутбук",
		"دفتر",
		"a b",
		"zero‌width",
		"tenant-1",
	]) {
		const { auth } = createFixture();
		const result = await auth.signIn({
			tenant: name,
			device: name,
			factor: claimsFactor({ ...goodClaims, externalId: name }),
			response: {},
		});

		expect(result.ok, name).toBe(true);
	}
});

test("a name that cannot be stored never reaches a store through a failing factor either", async () => {
	const { auth, calls } = createFixture();

	expect(
		await auth.signIn({
			tenant: "acme\u0000",
			device: "laptop",
			factor: {
				id: "f",
				strength: "possession",
				verify: async () => fail("x"),
			},
			response: {},
		}),
	).toEqual({ ok: false, error: "invalid-request" });
	expect(calls).toEqual([]);
});
