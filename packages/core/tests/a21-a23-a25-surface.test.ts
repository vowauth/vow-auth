import {
	createMemoryAccountStore,
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import * as core from "@vow-auth/core";
import { type AuthOptions, createAuth, succeed } from "@vow-auth/core";
import { factorPluginOf } from "@vow-auth/test-support";
import { expect, test } from "vitest";

const LIFE_TIME = 60_000;

const deepFreeze = <Value>(value: Value): Value => {
	if (typeof value === "object" && value !== null) {
		for (const nested of Object.values(value)) {
			deepFreeze(nested);
		}

		Object.freeze(value);
	}

	return value;
};

const optionsOf = (): AuthOptions => ({
	accounts: createMemoryAccountStore(),
	grants: createMemoryGrantStore(),
	tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
	meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	secrets: [{ version: 1, value: "surface-secret-0123456789abcdefghijklm" }],
	factors: {
		frozen: factorPluginOf(async () =>
			succeed(
				deepFreeze({
					provider: "email",
					externalId: "alice@example.com",
					email: "alice@example.com",
					emailVerified: true,
				}),
			),
		),
	},
	maximumLifeTimeMilliseconds: LIFE_TIME,
	sessionTimeToLiveMilliseconds: LIFE_TIME,
	registration: () => "allow",
	policy: () => "allow",
	audit: async () => undefined,
});

test("A21, A25: the public surface is exactly this, so a new export or a weakening option is a visible change", () => {
	expect(Object.keys(core).sort()).toEqual([
		"AUDIT_EVENTS",
		"AUDIT_OUTCOMES",
		"AUDIT_REASONS",
		"DECISION_KINDS",
		"DENY_REASONS",
		"EMAIL_PROVIDER",
		"ERROR_CODES",
		"MEMBERSHIP_OUTCOMES",
		"NO_LIMIT",
		"RESOLUTION_OUTCOMES",
		"applyLimit",
		"assertLimit",
		"assertLimitRule",
		"canonicalizeEmail",
		"createAuth",
		"createRedirectPolicy",
		"defineDuration",
		"defineMeterRule",
		"fail",
		"isStoreFullError",
		"report",
		"requireFactor",
		"slidingWindow",
		"storeFullError",
		"succeed",
	]);

	const optionKeys = {
		accounts: true,
		grants: true,
		tokenStore: true,
		meterStore: true,
		secrets: true,
		factors: true,
		trustedProviders: true,
		maximumLifeTimeMilliseconds: true,
		sessionTimeToLiveMilliseconds: true,
		stepUpTimeToLiveMilliseconds: true,
		registration: true,
		policy: true,
		audit: true,
	} satisfies Record<keyof AuthOptions, true>;

	expect(Object.keys(optionKeys)).toHaveLength(13);
});

test("A25: an unknown option is a compile error, not silence", () => {
	expect(() =>
		createAuth({
			...optionsOf(),
			// @ts-expect-error an option the core does not have
			failOpen: true,
		}),
	).not.toThrow();
});

test("A23: the core never changes what it is given", async () => {
	const auth = createAuth(deepFreeze(optionsOf()));

	expect((await auth.tenants.create("acme")).ok).toBe(true);

	const signedIn = await auth.signIn(
		deepFreeze({
			tenant: "acme",
			device: "laptop",
			factor: "frozen",
			response: { nested: { value: "x" } },
		}),
	);

	expect(signedIn.ok).toBe(true);

	if (signedIn.ok) {
		expect(
			(await auth.memberships.suspend("acme", signedIn.value.subject)).ok,
		).toBe(true);
		expect((await auth.accounts.delete(signedIn.value.account)).ok).toBe(true);
	}
});
