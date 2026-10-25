import {
	createMemoryAccountStore,
	createMemoryEpochStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AccountStore,
	type AuditRecord,
	type AuditSink,
	createAuth,
	fail,
	type RegistrationPolicyInput,
	requireFactor,
	type SecretVersion,
	type SignInPolicyInput,
	succeed,
} from "@vow-auth/core";
import { factorPluginOf } from "@vow-auth/test-support";
import { expect, test, vi } from "vitest";

const MINUTE = 60_000;
const GOOD_CODE = "424242";
const OLD_SECRET: SecretVersion = {
	version: 1,
	value: "accounts-secret-0123456789abcdefghij",
};
const NEW_SECRET: SecretVersion = {
	version: 2,
	value: "accounts-secret-2-ABCDEFGHIJKLMNOPQRST",
};

const textOf = (response: unknown, key: string): string =>
	typeof response === "object" && response !== null
		? String(Reflect.get(response, key) ?? "")
		: "";

const WRITES = [
	"createTenant",
	"setTenant",
	"setAccount",
	"createAccount",
	"linkIdentity",
	"updateIdentity",
	"createMembership",
	"setMembership",
	"evictEmailClaims",
	"deleteAccount",
] as const;

/** The store, and the names of the writes made through it, in order. */
const watch = (store: AccountStore) => {
	const writes: string[] = [];
	const watched: AccountStore = { ...store };

	for (const name of WRITES) {
		const write = store[name] as (...input: unknown[]) => Promise<unknown>;

		Object.assign(watched, {
			[name]: (...input: unknown[]) => {
				writes.push(name);

				return write(...input);
			},
		});
	}

	return { store: watched, writes };
};

type Options = {
	readonly registration?: (input: RegistrationPolicyInput) => unknown;
	readonly policy?: (input: SignInPolicyInput) => unknown;
	readonly trustedProviders?: readonly string[];
	readonly audit?: AuditSink;
	readonly store?: AccountStore;
	readonly secrets?: readonly SecretVersion[];
};

const createFixture = async (options: Options = {}) => {
	const base = options.store ?? createMemoryAccountStore();
	const { store, writes } = watch(base);
	const forgotten: string[] = [];
	const auth = createAuth({
		accounts: store,
		factors: {
			email: factorPluginOf(
				async (response) =>
					succeed({
						provider: "email",
						externalId: textOf(response, "email"),
						email: textOf(response, "email"),
						emailVerified: true,
					}),
				{
					providers: ["email"],
					forget: async (account) => {
						forgotten.push(account);
					},
				},
			),
			google: factorPluginOf(
				async (response) =>
					succeed({
						provider: "google",
						externalId: textOf(response, "id"),
						email: textOf(response, "email"),
						emailVerified: textOf(response, "verified") !== "no",
					}),
				{ providers: ["google"] },
			),
			password: factorPluginOf(
				async (response) =>
					succeed({
						provider: "password",
						externalId: textOf(response, "email"),
						email: textOf(response, "email"),
						emailVerified: false,
					}),
				{ providers: ["password"] },
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
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: options.secrets ?? [OLD_SECRET],
		trustedProviders: options.trustedProviders ?? ["email", "google"],
		maximumLifeTimeMilliseconds: 60 * MINUTE,
		sessionTimeToLiveMilliseconds: 30 * MINUTE,
		stepUpTimeToLiveMilliseconds: 5 * MINUTE,
		registration: options.registration ?? (() => "allow"),
		policy: options.policy ?? (() => "allow"),
		audit: options.audit ?? (async () => undefined),
	});

	if (options.store === undefined) {
		await auth.tenants.create("acme");
		await auth.tenants.create("globex");
	}

	writes.length = 0;

	const signIn = (
		tenant: string,
		factor: string,
		response: unknown,
		device = "laptop",
	) => auth.signIn({ tenant, device, factor, response });

	const signedIn = async (
		tenant: string,
		factor: string,
		response: unknown,
		device = "laptop",
	) => {
		const result = await signIn(tenant, factor, response, device);

		if (!result.ok) {
			throw new Error(`the sign in must pass: ${JSON.stringify(result)}`);
		}

		return result.value;
	};

	const isValid = async (token: string) =>
		(await auth.sessions.verify(token)).ok;

	return { auth, base, forgotten, isValid, signIn, signedIn, store, writes };
};

const stepUpOf = (result: {
	readonly ok: boolean;
	readonly error?: unknown;
}) => {
	const error = result.error;

	if (
		result.ok ||
		typeof error !== "object" ||
		error === null ||
		Reflect.get(error, "code") !== "step-up-required"
	) {
		throw new Error("a step-up was expected");
	}

	return String(Reflect.get(error, "continuation"));
};

test("one person in two tenants is one account and one identity, with a subject of its own in each", async () => {
	const { base, signedIn } = await createFixture();
	const inAcme = await signedIn("acme", "email", { email: "ivan@example.com" });
	const inGlobex = await signedIn("globex", "email", {
		email: "ivan@example.com",
	});

	expect(inAcme.identity).toBe("created");
	expect(inGlobex.identity).toBe("existing");
	expect(inGlobex.membership).toBe("created");
	expect(inGlobex.account).toBe(inAcme.account);
	expect(inGlobex.subject).not.toBe(inAcme.subject);
	expect(inAcme.account).toMatch(/^acc_[0-9a-f]{32}$/);
	expect(inAcme.subject).toMatch(/^sub_[0-9a-f]{32}$/);
	expect(await base.listMemberships(inAcme.account)).toHaveLength(2);
});

test("a subject removed from a tenant and let back in keeps its id", async () => {
	const seen: RegistrationPolicyInput[] = [];
	const { auth, isValid, signIn, signedIn } = await createFixture({
		registration: (input) => {
			seen.push(input);

			return "allow";
		},
	});
	const first = await signedIn("acme", "email", { email: "ivan@example.com" });

	expect((await auth.memberships.remove("acme", first.subject)).ok).toBe(true);
	expect(await isValid(first.token)).toBe(false);

	const back = await signIn("acme", "email", { email: "ivan@example.com" });

	expect(back.ok && back.value.subject).toBe(first.subject);
	expect(back.ok && back.value.membership).toBe("rejoined");
	expect(seen.map((input) => [input.newAccount, input.newMembership])).toEqual([
		[true, "created"],
		[false, "rejoined"],
	]);
});

test("a refused registration writes nothing, and the policy sees what would be created", async () => {
	const seen: RegistrationPolicyInput[] = [];
	const { signIn, writes } = await createFixture({
		registration: (input) => {
			seen.push(input);

			return "deny";
		},
	});

	expect(await signIn("acme", "email", { email: "ivan@example.com" })).toEqual({
		ok: false,
		error: "no-allow",
	});
	expect(writes).toEqual([]);
	expect(seen[0]).toMatchObject({
		tenant: "acme",
		newAccount: true,
		newMembership: "created",
		emailOwnedByAnotherAccount: false,
	});
	expect(seen[0]?.account).toMatch(/^acc_/);
	expect(seen[0]?.subject).toMatch(/^sub_/);
});

test("a sign in waiting for its second factor writes nothing, and writes everything once it passes", async () => {
	const { auth, isValid, signedIn, writes } = await createFixture({
		policy: (input) =>
			input.tenant === "globex" && input.proofs.length < 2
				? requireFactor("code")
				: "allow",
	});
	const squatter = await signedIn("acme", "password", {
		email: "ivan@example.com",
	});
	const step = (factor: string, response: unknown, continuation?: string) =>
		auth.signIn({
			tenant: "globex",
			device: "laptop",
			factor,
			response,
			...(continuation === undefined ? {} : { continuation }),
		});

	writes.length = 0;

	const continuation = stepUpOf(
		await step("email", { email: "ivan@example.com" }),
	);

	expect(writes).toEqual([]);
	expect(await isValid(squatter.token)).toBe(true);

	const done = await step("code", { code: GOOD_CODE }, continuation);

	expect(done.ok && done.value.identity).toBe("created");
	expect(writes).toEqual(["createAccount", "evictEmailClaims"]);
	expect(await isValid(squatter.token)).toBe(false);
});

test("a wrong second factor and a denied sign in write nothing either", async () => {
	const { auth, signedIn, isValid, writes } = await createFixture({
		policy: (input) => {
			if (input.tenant === "globex") {
				return "deny";
			}

			return input.proofs.length < 2 ? requireFactor("code") : "allow";
		},
	});
	const squatter = await auth.signIn({
		tenant: "acme",
		device: "phone",
		factor: "password",
		response: { email: "ivan@example.com" },
	});
	const squatterToken = stepUpOf(squatter);
	const squatterIn = await auth.signIn({
		tenant: "acme",
		device: "phone",
		factor: "code",
		response: { code: GOOD_CODE },
		continuation: squatterToken,
	});

	if (!squatterIn.ok) {
		throw new Error("the squatter signs in with two factors");
	}

	writes.length = 0;

	const challenge = stepUpOf(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email",
			response: { email: "ivan@example.com" },
		}),
	);
	const wrong = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "code",
		response: { code: "000000" },
		continuation: challenge,
	});
	const denied = await auth.signIn({
		tenant: "globex",
		device: "laptop",
		factor: "email",
		response: { email: "ivan@example.com" },
	});

	expect(wrong).toEqual({ ok: false, error: "invalid-proof" });
	expect(denied).toEqual({ ok: false, error: "no-allow" });
	expect(writes).toEqual([]);
	expect(await isValid(squatterIn.value.token)).toBe(true);

	void signedIn;
});

test("A9: proving an email evicts its unverified claims in the whole deployment, after the allow, with their sessions in every tenant", async () => {
	const { base, isValid, signedIn } = await createFixture();
	const squatterInAcme = await signedIn("acme", "password", {
		email: "victim@example.com",
	});
	const squatterInGlobex = await signedIn("globex", "password", {
		email: "victim@example.com",
	});
	const victim = await signedIn("acme", "email", {
		email: "victim@example.com",
	});

	expect(squatterInGlobex.account).toBe(squatterInAcme.account);
	expect(victim.account).not.toBe(squatterInAcme.account);
	expect(victim.evicted).toEqual([squatterInAcme.account]);
	expect(await isValid(squatterInAcme.token)).toBe(false);
	expect(await isValid(squatterInGlobex.token)).toBe(false);
	expect(await isValid(victim.token)).toBe(true);
	expect((await base.getAccount(squatterInAcme.account))?.evicted).toBe(true);
	expect(
		await base.findIdentity("password", "victim@example.com"),
	).toBeUndefined();
});

test("A9: an account with another identity stays, loses only the claim, and loses its sessions", async () => {
	const { base, isValid, signedIn } = await createFixture({
		trustedProviders: ["email"],
	});
	const mixed = await signedIn("acme", "google", {
		id: "g-1",
		email: "victim@example.com",
		verified: "no",
	});
	const victim = await signedIn("acme", "email", {
		email: "victim@example.com",
	});

	expect(victim.evicted).toEqual([mixed.account]);
	expect(await isValid(mixed.token)).toBe(false);
	expect(await base.findIdentity("google", "g-1")).toBeUndefined();
	expect((await base.getAccount(mixed.account))?.evicted).toBe(true);
});

test("linking by email needs a trusted provider; a verified email from another counts as unverified and is evicted by the owner", async () => {
	const seen: RegistrationPolicyInput[] = [];
	const { base, isValid, signedIn } = await createFixture({
		trustedProviders: ["email"],
		registration: (input) => {
			seen.push(input);

			return "allow";
		},
	});
	const owner = await signedIn("acme", "email", { email: "ivan@example.com" });
	const google = await signedIn("acme", "google", {
		id: "g-1",
		email: "ivan@example.com",
	});

	expect(google.identity).toBe("created");
	expect(google.account).not.toBe(owner.account);
	expect(seen[1]?.emailOwnedByAnotherAccount).toBe(true);

	const again = await signedIn("acme", "email", { email: "ivan@example.com" });

	expect(again.account).toBe(owner.account);
	expect(again.evicted).toEqual([google.account]);
	expect(await isValid(google.token)).toBe(false);
	expect(await base.findIdentity("google", "g-1")).toBeUndefined();
});

test("with the provider trusted, its verified email links to the account that owns the email", async () => {
	const { signedIn } = await createFixture();
	const owner = await signedIn("acme", "email", { email: "ivan@example.com" });
	const google = await signedIn("globex", "google", {
		id: "g-1",
		email: "ivan@example.com",
	});

	expect(google.identity).toBe("linked");
	expect(google.account).toBe(owner.account);
	expect(google.membership).toBe("created");
});

test("the data of the provider is updated at sign in, and sealed again", async () => {
	const { base, signedIn } = await createFixture({
		trustedProviders: ["email"],
	});
	const first = await signedIn("acme", "google", {
		id: "g-1",
		email: "old@example.com",
	});
	const before = await base.findIdentity("google", "g-1");
	const second = await signedIn("acme", "google", {
		id: "g-1",
		email: "new@example.com",
	});
	const after = await base.findIdentity("google", "g-1");

	expect(second.account).toBe(first.account);
	expect(after?.email).toBe("new@example.com");
	expect(after?.seal).not.toBe(before?.seal);
	expect(
		(await signedIn("acme", "google", { id: "g-1", email: "new@example.com" }))
			.account,
	).toBe(first.account);
});

test("a record changed or written past the engine refuses the sign in, and never turns into a new account", async () => {
	const fixture = await createFixture();
	const { base, signIn, signedIn } = fixture;
	const victim = await signedIn("acme", "email", {
		email: "victim@example.com",
	});
	const attacker = await signedIn("acme", "email", {
		email: "attacker@example.com",
	});
	const identity = await base.findIdentity("email", "attacker@example.com");

	expect(identity?.accountId).toBe(attacker.account);

	if (identity === undefined) {
		throw new Error("the identity must exist");
	}

	await base.updateIdentity(
		{ ...identity, accountId: victim.account },
		identity.seal,
	);

	expect(
		await signIn("acme", "email", { email: "attacker@example.com" }),
	).toEqual({ ok: false, error: "invalid-record" });

	await base.linkIdentity({
		provider: "google",
		externalId: "g-evil",
		accountId: victim.account,
		email: "victim@example.com",
		emailVerified: true,
		seal: "1.AAAA",
	});

	expect(
		await signIn("acme", "google", {
			id: "g-evil",
			email: "victim@example.com",
		}),
	).toEqual({ ok: false, error: "invalid-record" });

	const membership = await base.findMembership("acme", victim.account);

	if (membership === undefined) {
		throw new Error("the membership must exist");
	}

	const mallory = await signedIn("acme", "email", {
		email: "mallory@example.com",
	});
	const { store } = fixture;
	const findMembership = store.findMembership;

	store.findMembership = async (tenant, account) =>
		account === mallory.account
			? { ...membership, accountId: mallory.account }
			: findMembership(tenant, account);

	expect(
		await signIn("acme", "email", { email: "mallory@example.com" }),
	).toEqual({ ok: false, error: "invalid-record" });
});

test("a suspension cleared past the engine, or a tenant enabled past it, does not let anyone in", async () => {
	const { auth, base, signIn, signedIn } = await createFixture();
	const ivan = await signedIn("acme", "email", { email: "ivan@example.com" });

	await auth.memberships.suspend("acme", ivan.subject);

	const suspended = await base.getMembership("acme", ivan.subject);

	if (suspended === undefined) {
		throw new Error("the membership must exist");
	}

	await base.setMembership({ ...suspended, status: "active" }, suspended.seal);

	expect(await signIn("acme", "email", { email: "ivan@example.com" })).toEqual({
		ok: false,
		error: "invalid-record",
	});

	await auth.tenants.disable("globex");

	const disabled = await base.getTenant("globex");

	if (disabled === undefined) {
		throw new Error("the tenant must exist");
	}

	await base.setTenant({ ...disabled, disabled: false }, disabled.seal);

	expect(
		await signIn("globex", "email", { email: "ivan@example.com" }),
	).toEqual({ ok: false, error: "invalid-record" });
});

test("a tenant that does not exist or is disabled lets nobody in, and disabling it ends its sessions", async () => {
	const { auth, isValid, signIn, signedIn } = await createFixture();
	const ivan = await signedIn("globex", "email", { email: "ivan@example.com" });

	expect(
		await signIn("nowhere", "email", { email: "ivan@example.com" }),
	).toEqual({
		ok: false,
		error: "no-tenant",
	});
	expect(await auth.tenants.disable("globex")).toEqual({
		ok: true,
		value: "globex",
	});
	expect(await isValid(ivan.token)).toBe(false);
	expect(
		await signIn("globex", "email", { email: "ivan@example.com" }),
	).toEqual({
		ok: false,
		error: "no-tenant",
	});
	expect((await auth.tenants.enable("globex")).ok).toBe(true);
	expect(
		(await signIn("globex", "email", { email: "ivan@example.com" })).ok,
	).toBe(true);
	expect(await auth.tenants.create("globex")).toEqual({
		ok: false,
		error: "conflict",
	});
	expect(await auth.tenants.disable("nowhere")).toEqual({
		ok: false,
		error: "no-tenant",
	});
	expect(await auth.tenants.create("")).toEqual({
		ok: false,
		error: "invalid-request",
	});
});

test("a suspended membership is refused until it is restored, with its sessions gone", async () => {
	const { auth, isValid, signIn, signedIn } = await createFixture();
	const ivan = await signedIn("acme", "email", { email: "ivan@example.com" });
	const elsewhere = await signedIn("globex", "email", {
		email: "ivan@example.com",
	});

	expect(await auth.memberships.suspend("acme", ivan.subject)).toEqual({
		ok: true,
		value: { tenant: "acme", subject: ivan.subject, status: "suspended" },
	});
	expect(await isValid(ivan.token)).toBe(false);
	expect(await isValid(elsewhere.token)).toBe(true);
	expect(await signIn("acme", "email", { email: "ivan@example.com" })).toEqual({
		ok: false,
		error: "suspended",
	});
	expect((await auth.memberships.restore("acme", ivan.subject)).ok).toBe(true);

	const back = await signIn("acme", "email", { email: "ivan@example.com" });

	expect(back.ok && back.value.subject).toBe(ivan.subject);
	expect(back.ok && back.value.membership).toBe("existing");
	expect(await auth.memberships.suspend("globex", ivan.subject)).toEqual({
		ok: false,
		error: "no-subject",
	});
});

test("A10: deleting an account takes its identities and the data of its factors, ends its sessions everywhere, and leaves its subjects without it", async () => {
	const { auth, base, forgotten, isValid, signedIn } = await createFixture();
	const inAcme = await signedIn("acme", "email", { email: "ivan@example.com" });
	const inGlobex = await signedIn("globex", "email", {
		email: "ivan@example.com",
	});
	const deleted = await auth.accounts.delete(inAcme.account);

	expect(
		deleted.ok &&
			[...deleted.value].sort((a, b) => a.tenant.localeCompare(b.tenant)),
	).toEqual([
		{ tenant: "acme", subject: inAcme.subject, status: "removed" },
		{ tenant: "globex", subject: inGlobex.subject, status: "removed" },
	]);
	expect(forgotten).toEqual([inAcme.account]);
	expect(await isValid(inAcme.token)).toBe(false);
	expect(await isValid(inGlobex.token)).toBe(false);
	expect(await base.getAccount(inAcme.account)).toBeUndefined();
	expect(await base.findIdentity("email", "ivan@example.com")).toBeUndefined();
	expect(await base.getMembership("acme", inAcme.subject)).toMatchObject({
		accountId: undefined,
		status: "removed",
	});
	expect(await auth.memberships.restore("acme", inAcme.subject)).toEqual({
		ok: false,
		error: "no-subject",
	});

	const again = await signedIn("acme", "email", { email: "ivan@example.com" });

	expect(again.identity).toBe("created");
	expect(again.account).not.toBe(inAcme.account);
	expect(again.subject).not.toBe(inAcme.subject);
	expect(await auth.accounts.delete(inAcme.account)).toEqual({
		ok: false,
		error: "no-subject",
	});
});

test("sessions are revoked before the store changes, so a failure never leaves a live session", async () => {
	const base = createMemoryAccountStore();
	const { auth, isValid, signedIn } = await createFixture({
		store: {
			...base,
			deleteAccount: async () => {
				throw new Error("the database is down");
			},
		},
	});

	await auth.tenants.create("acme");

	const ivan = await signedIn("acme", "email", { email: "ivan@example.com" });

	await expect(auth.accounts.delete(ivan.account)).rejects.toThrow(
		"the database is down",
	);
	expect(await isValid(ivan.token)).toBe(false);
	expect(await base.getAccount(ivan.account)).toBeDefined();
});

test("a failing sink during a change that takes access away still leaves the sessions revoked", async () => {
	const records: AuditRecord[] = [];
	let failing = false;
	const { auth, isValid, signedIn } = await createFixture({
		audit: async (record) => {
			if (failing) {
				throw new Error("the audit store is down");
			}

			records.push(record);
		},
	});
	const ivan = await signedIn("acme", "email", { email: "ivan@example.com" });

	failing = true;

	await expect(auth.memberships.suspend("acme", ivan.subject)).rejects.toThrow(
		"the audit store is down",
	);

	failing = false;

	expect(await isValid(ivan.token)).toBe(false);

	records.length = 0;

	await auth.memberships.suspend("acme", ivan.subject);
	await auth.memberships.restore("acme", ivan.subject);
	await auth.accounts.delete(ivan.account);

	expect(
		records.map((record) => [record.event, record.outcome, record.reason]),
	).toEqual([
		["session.revoke", "success", "revoked"],
		["membership.change", "success", "suspended"],
		["membership.change", "success", "restored"],
		["session.revoke", "success", "revoked"],
		["account.delete", "success", "deleted"],
	]);
});

test("a change that gives access back is recorded before it is made, so a failing sink stops it", async () => {
	let failing = false;
	const { auth, base, signedIn } = await createFixture({
		audit: async () => {
			if (failing) {
				throw new Error("the audit store is down");
			}
		},
	});
	const ivan = await signedIn("acme", "email", { email: "ivan@example.com" });

	await auth.memberships.suspend("acme", ivan.subject);
	failing = true;

	await expect(auth.memberships.restore("acme", ivan.subject)).rejects.toThrow(
		"the audit store is down",
	);
	expect((await base.getMembership("acme", ivan.subject))?.status).toBe(
		"suspended",
	);
});

test("concurrent first sign ins of one person make one account; the losers are told to try again", async () => {
	const { base, signIn } = await createFixture();
	const results = await Promise.all(
		Array.from({ length: 10 }, (_, index) =>
			signIn("acme", "email", { email: "ivan@example.com" }, `device-${index}`),
		),
	);
	const owner = await base.findIdentity("email", "ivan@example.com");
	const passed = results.filter((result) => result.ok);

	expect(passed.length).toBeGreaterThanOrEqual(1);
	expect(
		new Set(passed.map((result) => result.ok && result.value.account)),
	).toEqual(new Set([owner?.accountId]));
	expect(
		results.every((result) => result.ok || result.error === "conflict"),
	).toBe(true);
	expect(await base.listMemberships(owner?.accountId ?? "")).toHaveLength(1);
});

test("records sealed under an older secret are sealed again under the newest at their next sign in", async () => {
	const store = createMemoryAccountStore();
	const old = await createFixture({ store, secrets: [OLD_SECRET] });

	await old.auth.tenants.create("acme");

	const ivan = await old.signedIn("acme", "email", {
		email: "ivan@example.com",
	});
	const rotated = await createFixture({
		store,
		secrets: [NEW_SECRET, OLD_SECRET],
	});
	const again = await rotated.signedIn("acme", "email", {
		email: "ivan@example.com",
	});

	expect(again.subject).toBe(ivan.subject);
	expect((await store.findIdentity("email", "ivan@example.com"))?.seal).toMatch(
		/^2\./,
	);
	expect((await store.getMembership("acme", ivan.subject))?.seal).toMatch(
		/^2\./,
	);
	expect((await store.getAccount(ivan.account))?.seal).toMatch(/^2\./);
	expect((await store.getTenant("acme"))?.seal).toMatch(/^2\./);

	const withoutOld = await createFixture({ store, secrets: [NEW_SECRET] });

	expect(
		(await withoutOld.signIn("acme", "email", { email: "ivan@example.com" }))
			.ok,
	).toBe(true);
});

test("a record whose secret is no longer listed does not open", async () => {
	const store = createMemoryAccountStore();
	const old = await createFixture({ store, secrets: [OLD_SECRET] });

	await old.auth.tenants.create("acme");
	await old.signedIn("acme", "email", { email: "ivan@example.com" });

	const forgetful = await createFixture({ store, secrets: [NEW_SECRET] });

	expect(
		await forgetful.signIn("acme", "email", { email: "ivan@example.com" }),
	).toEqual({ ok: false, error: "invalid-record" });
});

test("registration is required, and a trusted provider must be one a factor claims", () => {
	const options = {
		accounts: createMemoryAccountStore(),
		factors: { email: factorPluginOf(async () => succeed({})) },
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [OLD_SECRET],
		maximumLifeTimeMilliseconds: MINUTE,
		sessionTimeToLiveMilliseconds: MINUTE,
		registration: () => "allow",
		policy: () => "allow",
		audit: async () => undefined,
	};

	expect(() => createAuth(options)).not.toThrow();
	expect(() =>
		createAuth({ ...options, registration: undefined as never }),
	).toThrow(TypeError);
	expect(() =>
		createAuth({ ...options, trustedProviders: ["google"] }),
	).toThrow(RangeError);
	expect(() => createAuth({ ...options, trustedProviders: [""] })).toThrow(
		RangeError,
	);
	expect(vi.isMockFunction(options.policy)).toBe(false);
});
