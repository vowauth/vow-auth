import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
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
	identities: createMemoryIdentityStore(),
	epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
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
		"IDENTITY_CHANGE_TYPES",
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
		identities: true,
		epochs: true,
		tokenStore: true,
		meterStore: true,
		secrets: true,
		factors: true,
		maximumLifeTimeMilliseconds: true,
		sessionTimeToLiveMilliseconds: true,
		stepUpTimeToLiveMilliseconds: true,
		policy: true,
		audit: true,
	} satisfies Record<keyof AuthOptions, true>;

	expect(Object.keys(optionKeys)).toHaveLength(11);
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
			(
				await auth.mutateIdentity(
					"acme",
					signedIn.value.subject,
					deepFreeze({ type: "delete" }),
				)
			).ok,
		).toBe(true);
	}
});
