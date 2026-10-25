import {
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { type AccountStore, createAuth, fail, succeed } from "@vow-auth/core";
import { durationOf, factorPluginOf } from "@vow-auth/test-support";
import fastCheck from "fast-check";
import { expect, test } from "vitest";
import { accountsWith } from "./support/accounts.js";

const MINUTE = 60_000;
const SECRETS = [
	{ version: 1, value: "storable-secret-0123456789abcdefghijk" },
];

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

const claimsFactor = factorPluginOf(async (claims) => succeed(claims), {
	providers: ["idp"],
});

const goodClaims = {
	provider: "idp",
	externalId: "alice",
	emailVerified: false,
};

const createFixture = () => {
	const calls: string[] = [];
	const accounts: AccountStore = spyOn(accountsWith(["acme"], SECRETS), calls);
	const auth = createAuth({
		factors: {
			claims: claimsFactor,
			failing: factorPluginOf(async () => fail("x")),
		},
		accounts,
		grants: spyOn(createMemoryGrantStore(), calls),
		tokenStore: spyOn(
			createMemoryTokenStore({ maximumBytes: 1_000_000 }),
			calls,
		),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: SECRETS,
		maximumLifeTimeMilliseconds: 60 * MINUTE,
		sessionTimeToLiveMilliseconds: 30 * MINUTE,
		registration: () => "allow",
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
				factor: "claims",
				response: goodClaims,
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
					response: { ...goodClaims, provider: bad },
				}),
			).toEqual({ ok: false, error: "invalid-proof" });
			expect(
				await auth.signIn({
					...request,
					response: { ...goodClaims, externalId: bad },
				}),
			).toEqual({ ok: false, error: "invalid-proof" });
			for (const refused of [
				await auth.memberships.suspend(bad, "subject"),
				await auth.memberships.remove("acme", bad),
				await auth.accounts.delete(bad),
				await auth.tenants.create(bad),
				await auth.tenants.disable(bad),
			]) {
				expect(refused).toEqual({ ok: false, error: "invalid-request" });
			}
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
		factor: "claims",
		response: goodClaims,
	});

	if (!signedIn.ok) {
		throw new Error("the sign in must pass");
	}

	calls.length = 0;

	await fastCheck.assert(
		fastCheck.asyncProperty(cannotBeStored, async (bad) => {
			expect(
				await auth.agents.delegate(signedIn.value.token, {
					tenant: "acme",
					agent: bad,
					timeToLive: durationOf(MINUTE),
				}),
			).toEqual({ ok: false, error: "invalid-request" });
		}),
		{ numRuns: 100 },
	);
	expect(calls.filter((name) => name === "revoke")).toEqual([]);
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

		expect((await auth.tenants.create(name)).ok, name).toBe(true);

		const result = await auth.signIn({
			tenant: name,
			device: name,
			factor: "claims",
			response: { ...goodClaims, externalId: name },
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
			factor: "failing",
			response: {},
		}),
	).toEqual({ ok: false, error: "invalid-request" });
	expect(calls).toEqual([]);
});
