import {
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AuditRecord,
	type AuditSink,
	type AuthFactors,
	type AuthOptions,
	createAuth,
	type FactorCapabilities,
	type FactorPlugin,
	fail,
	requireFactor,
	succeed,
} from "@vow-auth/core";
import {
	durationOf,
	factorPluginOf,
	meterRuleOf,
} from "@vow-auth/test-support";
import { expect, test } from "vitest";
import { accountsWith } from "./support/accounts.js";

const LIFE_TIME = 60_000;
const AUTH_SECRETS = [
	{ version: 1, value: "auth-secret-0123456789abcdefghijklmnop" },
];

const aliceClaims = {
	provider: "email",
	externalId: "alice@example.com",
	email: "alice@example.com",
	emailVerified: true,
};

const emailFactor = factorPluginOf(async () => succeed(aliceClaims), {
	providers: ["email"],
});

/** A factor that redeems the tokens of its own domain, as an email link does. */
const linkFactor: FactorPlugin<{
	issue(email: string): Promise<string>;
}> = {
	strength: "possession",
	providers: ["email"],
	create: ({ tokens }) => ({
		async verify(response) {
			if (typeof response !== "string") {
				return fail("invalid-token");
			}

			const consumed = await tokens.consume(response, "email-link");

			return consumed.ok
				? succeed({
						provider: "email",
						externalId: consumed.value.email,
						email: consumed.value.email,
						emailVerified: true,
					})
				: consumed;
		},
		api: {
			issue: (email) =>
				tokens.issue({
					purpose: "email-link",
					payload: { email },
					timeToLive: durationOf(LIFE_TIME),
				}),
		},
	}),
};

/** A factor written to break in: it keeps the capabilities it was given. */
const createEvilFactor = () => {
	const held: { capabilities?: FactorCapabilities } = {};
	const plugin: FactorPlugin<Record<string, never>> = {
		strength: "possession",
		providers: ["evil"],
		create(capabilities) {
			held.capabilities = capabilities;

			return { verify: async () => fail("invalid-proof"), api: {} };
		},
	};

	return { plugin, held };
};

const optionsWith = <Factors extends AuthFactors>(
	audit: AuditSink,
	factors: Factors,
): AuthOptions<Factors> => ({
	accounts: accountsWith(["acme"], AUTH_SECRETS),
	grants: createMemoryGrantStore(),
	tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
	meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	secrets: AUTH_SECRETS,
	factors,
	maximumLifeTimeMilliseconds: LIFE_TIME,
	sessionTimeToLiveMilliseconds: LIFE_TIME,
	registration: () => "allow",
	policy: () => "allow",
	audit,
});

const quiet = async () => undefined;

test("the audit sink is required, and a missing one is refused when the types are bypassed", () => {
	const { audit: _omitted, ...withoutAudit } = optionsWith(quiet, {
		email: emailFactor,
	});

	expect(() => {
		// @ts-expect-error the audit sink is required
		createAuth(withoutAudit);
	}).toThrow(TypeError);
	expect(() =>
		Reflect.apply(createAuth, undefined, [{ ...withoutAudit, audit: "log" }]),
	).toThrow(TypeError);
});

test("one sink reaches every part of the core", async () => {
	const records: AuditRecord[] = [];
	const auth = createAuth(
		optionsWith(
			async (record) => {
				records.push(record);
			},
			{ email: emailFactor, link: linkFactor },
		),
	);

	await auth.factors.link.issue("bob@example.com");
	await auth.devices.open("1.garbage");

	const signedIn = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "email",
		response: undefined,
	});

	if (!signedIn.ok) {
		throw new Error("the sign in must pass");
	}

	await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "link",
		response: "0".repeat(64),
	});

	const limiter = auth.createLimiter<string>({
		rule: meterRuleOf({ limit: 1, windowMilliseconds: 1_000 }),
		scopes: (actor) => [{ tenant: "acme", actor, resource: "email-link" }],
	});

	expect((await limiter("alice")).ok).toBe(true);
	expect(await limiter("alice")).toMatchObject({
		ok: false,
		error: { code: "rate-limited" },
	});
	await auth.sessions.verify("1.garbage", "acme");
	await auth.sessions.revoke({ tenant: "acme", scope: "tenant" });
	await auth.accounts.delete(signedIn.value.account);

	expect([...new Set(records.map((record) => record.event))].sort()).toEqual([
		"account.delete",
		"identity.resolve",
		"meter.consume",
		"policy.evaluate",
		"proof.verify",
		"seal.unseal",
		"session.issue",
		"session.revoke",
		"session.verify",
		"token.consume",
		"token.issue",
	]);
});

test("a failing sink stops every part that grants something", async () => {
	const auth = createAuth(
		optionsWith(
			async () => {
				throw new Error("the audit store is down");
			},
			{ email: emailFactor, link: linkFactor },
		),
	);

	await expect(auth.factors.link.issue("bob@example.com")).rejects.toThrow(
		"the audit store is down",
	);
	await expect(
		auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email",
			response: undefined,
		}),
	).rejects.toThrow("the audit store is down");
});

test("no part of the core issues anything for its caller", () => {
	const auth = createAuth(optionsWith(quiet, { email: emailFactor }));

	expect(Object.keys(auth).sort()).toEqual([
		"accounts",
		"agents",
		"createLimiter",
		"devices",
		"factors",
		"memberships",
		"sessions",
		"signIn",
		"tenants",
	]);
	expect(Object.keys(auth.sessions).sort()).toEqual([
		"end",
		"enter",
		"revoke",
		"verify",
	]);
	expect(Object.keys(auth.accounts)).toEqual(["delete"]);
	expect(Object.keys(auth.memberships).sort()).toEqual([
		"remove",
		"restore",
		"suspend",
	]);
	expect(Object.keys(auth.tenants).sort()).toEqual([
		"create",
		"disable",
		"enable",
	]);
	expect(auth.factors).toEqual({ email: {} });
	expect(Object.isFrozen(auth.factors)).toBe(true);
});

test("a sign in cannot bring a factor of its own, only name one the core was built with", async () => {
	const auth = createAuth(optionsWith(quiet, { email: emailFactor }));
	const ownFactor = {
		id: "email",
		strength: "possession",
		verify: async () => succeed(aliceClaims),
	};

	for (const factor of ["unknown", "constructor", "__proto__", "", ownFactor]) {
		expect(
			await auth.signIn({
				tenant: "acme",
				device: "laptop",
				// @ts-expect-error a factor of the caller's own is not a factor id
				factor,
				response: undefined,
			}),
			String(factor),
		).toEqual({ ok: false, error: "invalid-request" });
	}
});

test("a factor cannot claim the accounts of a provider it was not built for", async () => {
	const records: AuditRecord[] = [];
	const auth = createAuth(
		optionsWith(
			async (record) => {
				records.push(record);
			},
			{
				github: factorPluginOf(async () => succeed(aliceClaims), {
					providers: ["github"],
				}),
			},
		),
	);

	expect(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "github",
			response: undefined,
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
	expect(records).toEqual([
		expect.objectContaining({
			event: "proof.verify",
			outcome: "refusal",
			reason: "foreign-provider",
		}),
	]);
});

test("a factor seals nothing that opens as a session, an agent or a device", async () => {
	const { plugin, held } = createEvilFactor();
	const auth = createAuth(optionsWith(quiet, { evil: plugin }));
	const sealer = held.capabilities?.sealer;

	if (sealer === undefined) {
		throw new Error("the engine must create the factor");
	}

	const now = Date.now();
	const future = now + 10 ** 12;
	const hour = durationOf(3_600_000);
	const session = await sealer.seal({
		purpose: "session",
		payload: {
			chain: JSON.stringify([
				{ scope: "tenant", id: "acme", stamp: future },
				{ scope: "user", id: "anyone", stamp: future },
				{ scope: "device", id: "laptop", stamp: future },
				{ scope: "session", id: "s-1", stamp: future },
			]),
			expiresAtMilliseconds: String(now + 3_600_000),
			authenticatedAtMilliseconds: String(now),
			methods: JSON.stringify(["totp"]),
		},
		timeToLive: hour,
	});
	const agent = await sealer.seal({
		purpose: "agent",
		payload: {
			chain: JSON.stringify([
				{ scope: "tenant", id: "acme", stamp: future },
				{ scope: "user", id: "anyone", stamp: future },
				{ scope: "agent", id: "bot", stamp: future },
				{ scope: "delegation", id: "d-1", stamp: future },
			]),
			expiresAtMilliseconds: String(now + 3_600_000),
			delegatedAtMilliseconds: String(now),
		},
		timeToLive: hour,
	});
	const device = await sealer.seal({
		purpose: "device",
		payload: { id: "a".repeat(64) },
		timeToLive: hour,
	});

	expect(await auth.sessions.verify(session, "acme")).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.agents.verify(agent)).toEqual({
		ok: false,
		error: "invalid-session",
	});
	expect(await auth.devices.open(device)).toBeUndefined();
});

test("a factor issues no token that continues a sign in or opens another factor", async () => {
	const records: AuditRecord[] = [];
	const { plugin, held } = createEvilFactor();
	const auth = createAuth({
		...optionsWith(
			async (record) => {
				records.push(record);
			},
			{ evil: plugin, link: linkFactor },
		),
		stepUpTimeToLiveMilliseconds: 60_000,
		policy: () => requireFactor("link"),
	});
	const tokens = held.capabilities?.tokens;

	if (tokens === undefined) {
		throw new Error("the engine must create the factor");
	}

	const continuation = await tokens.issue({
		purpose: "sign-in-continuation",
		payload: { tenant: "acme", device: "laptop", factor: "link" },
		timeToLive: durationOf(LIFE_TIME),
	});
	const link = await tokens.issue({
		purpose: "email-link",
		payload: { email: "victim@example.com" },
		timeToLive: durationOf(LIFE_TIME),
	});

	records.length = 0;

	expect(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "link",
			response: undefined,
			continuation,
		}),
	).toEqual({ ok: false, error: "invalid-token" });
	expect(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "link",
			response: link,
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
	expect(
		records
			.filter((record) => record.event === "token.consume")
			.map((record) => record.reason),
	).toEqual(["wrong-purpose", "wrong-purpose"]);
});

test("the application manages tenants, memberships and accounts, but has no way to create an account, link an identity or confirm an email", async () => {
	const auth = createAuth(optionsWith(quiet, { email: emailFactor }));
	const signedIn = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "email",
		response: undefined,
	});

	expect(signedIn.ok).toBe(true);

	for (const part of [auth.accounts, auth.memberships, auth.tenants]) {
		for (const name of Object.keys(part)) {
			expect(name).not.toMatch(/create.*account|link|confirm|grant|issue/i);
		}
	}

	expect(
		// @ts-expect-error an account cannot be created by the application
		auth.accounts.create,
	).toBeUndefined();
});

test("factors without the providers they may claim stop the start", () => {
	for (const providers of [[], [""], "email", undefined]) {
		expect(() =>
			createAuth(
				optionsWith(quiet, {
					broken: {
						strength: "possession",
						// @ts-expect-error providers must be a list of names
						providers,
						create: () => ({ verify: async () => fail("x"), api: {} }),
					},
				}),
			),
		).toThrow(RangeError);
	}

	expect(() =>
		// @ts-expect-error the factors are required
		createAuth({ ...optionsWith(quiet, {}), factors: undefined }),
	).toThrow(TypeError);
});

test("a second factor may repeat who the first one proved, and may not name anyone else", async () => {
	const records: AuditRecord[] = [];
	const auth = createAuth({
		...optionsWith(
			async (record) => {
				records.push(record);
			},
			{
				email: emailFactor,
				code: factorPluginOf(async (response) => succeed(response), {
					providers: ["code"],
				}),
			},
		),
		stepUpTimeToLiveMilliseconds: 60_000,
		policy: ({ proofs }) =>
			proofs.length > 1 ? "allow" : requireFactor("code"),
	});
	const continuation = async () => {
		const first = await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email",
			response: undefined,
		});

		if (first.ok || typeof first.error === "string") {
			throw new Error("a step-up was expected");
		}

		return first.error.continuation;
	};
	const secondStep = async (claims: unknown) =>
		auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "code",
			response: claims,
			continuation: await continuation(),
		});

	expect((await secondStep(aliceClaims)).ok).toBe(true);

	records.length = 0;

	expect(
		await secondStep({
			...aliceClaims,
			externalId: "mallory@example.com",
			email: "mallory@example.com",
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
	expect(await secondStep({ ...aliceClaims, emailVerified: false })).toEqual({
		ok: false,
		error: "invalid-proof",
	});
	expect(
		records
			.filter((record) => record.event === "proof.verify")
			.map((record) => record.reason),
	).toEqual(["verified", "foreign-provider", "verified", "foreign-provider"]);
});

test("a factor id is a plain name, so it cannot be shaped into another domain", () => {
	for (const id of ["Email", "x/y", "a b", "1factor", "", "-x"]) {
		expect(
			() => createAuth(optionsWith(quiet, { [id]: emailFactor })),
			id,
		).toThrow(RangeError);
	}
});
