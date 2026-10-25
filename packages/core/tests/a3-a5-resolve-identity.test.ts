import {
	applyPlan,
	canonicalizeEmail,
	type Factor,
	planSignIn,
	type SignInPlan,
	succeed,
	verifyProof,
} from "@vow-auth/core/internal";
import fastCheck from "fast-check";
import { expect, test } from "vitest";
import { createAccounts } from "./support/accounts.js";

type Accounts = Awaited<ReturnType<typeof createAccounts>>;

const proveClaims = async (claims: unknown) => {
	const factor: Factor = {
		id: "test-factor",
		strength: "possession",
		verify: async () => succeed(claims),
	};
	const result = await verifyProof(factor, undefined);

	if (!result.ok) {
		throw new Error("test proof was rejected");
	}

	return result.value;
};

const emailProof = (email: string, emailVerified: boolean) =>
	proveClaims({ provider: "email", externalId: email, email, emailVerified });

const googleProof = (
	externalId: string,
	email: string,
	emailVerified: boolean,
) => proveClaims({ provider: "google", externalId, email, emailVerified });

const optionsOf = (
	accounts: Accounts,
	trustedProviders: readonly string[] = ["email", "google"],
) => ({ store: accounts.store, records: accounts.records, trustedProviders });

/** Plans a sign in and writes it, as an allowed sign in does. */
const resolve = async (
	accounts: Accounts,
	tenant: string,
	proof: unknown,
	trustedProviders?: readonly string[],
) => {
	const options = optionsOf(accounts, trustedProviders);
	const plan = await planSignIn(options, tenant, proof);

	if (!plan.ok) {
		return plan;
	}

	const applied = await applyPlan(
		{ ...options, revoke: async () => undefined },
		plan.value,
	);

	return applied.ok ? succeed(plan.value) : applied;
};

const accountOf = (result: { ok: boolean; value?: SignInPlan }) =>
	result.ok ? result.value?.accountId : undefined;

test("the same identity resolves to the same account and subject", async () => {
	const accounts = await createAccounts(["t1"]);
	const first = await resolve(
		accounts,
		"t1",
		await emailProof("a@example.com", true),
	);
	const second = await resolve(
		accounts,
		"t1",
		await emailProof("a@example.com", true),
	);

	expect(first.ok && first.value.identity).toBe("created");
	expect(second.ok && second.value.identity).toBe("existing");
	expect(second.ok && second.value.membership).toBe("existing");
	expect(first.ok && first.value.subjectId).toBe(
		second.ok && second.value.subjectId,
	);
	expect(accountOf(first)).toBe(accountOf(second));
});

test("A3: a verified email of a trusted provider links a new identity to the account that owns the email", async () => {
	const accounts = await createAccounts(["t1"]);
	const created = await resolve(
		accounts,
		"t1",
		await emailProof("a@example.com", true),
	);
	const linked = await resolve(
		accounts,
		"t1",
		await googleProof("g-1", "a@example.com", true),
	);

	expect(linked.ok && linked.value.identity).toBe("linked");
	expect(accountOf(linked)).toBe(accountOf(created));
	expect(linked.ok && linked.value.subjectId).toBe(
		created.ok && created.value.subjectId,
	);
});

test("A3: a verified email of a provider that is not trusted links to nobody, and the registration learns the email is taken", async () => {
	const accounts = await createAccounts(["t1"]);
	const owner = await resolve(
		accounts,
		"t1",
		await emailProof("a@example.com", true),
		["email"],
	);
	const other = await planSignIn(
		optionsOf(accounts, ["email"]),
		"t1",
		await googleProof("g-1", "a@example.com", true),
	);

	expect(other.ok && other.value.identity).toBe("created");
	expect(other.ok && other.value.accountId).not.toBe(accountOf(owner));
	expect(other.ok && other.value.emailOwnedByAnotherAccount).toBe(true);
	expect(other.ok && other.value.verifiedEmail).toBeUndefined();
});

test("A3: a link to an owner deleted in the meantime is refused and never brings the owner back", async () => {
	const accounts = await createAccounts(["t1"]);
	const created = await resolve(
		accounts,
		"t1",
		await emailProof("a@example.com", true),
	);
	const owner = accountOf(created) ?? "";
	const options = optionsOf(accounts);
	const plan = await planSignIn(
		options,
		"t1",
		await googleProof("g-1", "a@example.com", true),
	);

	if (!plan.ok) {
		throw new Error("the link must be planned");
	}

	await accounts.store.deleteAccount(owner);

	expect(
		await applyPlan({ ...options, revoke: async () => undefined }, plan.value),
	).toEqual({ ok: false, error: "conflict" });
	expect(await accounts.store.getAccount(owner)).toBeUndefined();
	expect(await accounts.store.findIdentity("google", "g-1")).toBeUndefined();
});

test("A3: an unverified email never links to an existing account", async () => {
	const accounts = await createAccounts(["t1"]);
	const victim = await resolve(
		accounts,
		"t1",
		await emailProof("victim@example.com", true),
	);
	const attacker = await resolve(
		accounts,
		"t1",
		await googleProof("g-attacker", "victim@example.com", false),
	);

	expect(attacker.ok && attacker.value.identity).toBe("created");
	expect(accountOf(attacker)).not.toBe(accountOf(victim));
});

test("A3: a verified email does not link to an account whose email was never verified", async () => {
	const accounts = await createAccounts(["t1"]);
	const squatter = await resolve(
		accounts,
		"t1",
		await googleProof("g-squatter", "victim@example.com", false),
	);
	const victim = await resolve(
		accounts,
		"t1",
		await emailProof("victim@example.com", true),
	);

	expect(victim.ok && victim.value.identity).toBe("created");
	expect(accountOf(victim)).not.toBe(accountOf(squatter));
});

test("A4: email spelling variants resolve to one account", async () => {
	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.constantFrom(
				"alice@example.com",
				"ALICE@EXAMPLE.COM",
				"  Alice@Example.Com  ",
				"alice@EXAMPLE.com\t",
			),
			async (variant) => {
				const accounts = await createAccounts(["t1"]);
				const reference = await resolve(
					accounts,
					"t1",
					await emailProof("alice@example.com", true),
				);
				const resolved = await resolve(
					accounts,
					"t1",
					await emailProof(variant, true),
				);

				expect(accountOf(resolved)).toBe(accountOf(reference));
			},
		),
	);
});

test("A4: internationalized domains resolve to their punycode form", async () => {
	const accounts = await createAccounts(["t1"]);
	const unicode = await resolve(
		accounts,
		"t1",
		await emailProof("a@bücher.example", true),
	);
	const punycode = await resolve(
		accounts,
		"t1",
		await emailProof("a@xn--bcher-kva.example", true),
	);

	expect(accountOf(unicode)).toBe(accountOf(punycode));
});

test("A4: letters of any script are allowed in the local part", async () => {
	const accounts = await createAccounts(["t1"]);

	for (const email of ["bücher@example.com", "пользователь@example.com"]) {
		const result = await resolve(accounts, "t1", await emailProof(email, true));

		expect(result.ok, email).toBe(true);
	}
});

test("A4: malformed emails are refused at the gate, before any identity work", async () => {
	for (const email of [
		"no-at-sign",
		"two@@example.com",
		"a@b@example.com",
		"@example.com",
		"a@",
		"a b@example.com",
		"a@exa mple.com",
		"a@example.com:8080",
		"a@example.com/path",
		"a..b@example.com",
		".a@example.com",
		"a.@example.com",
		"a@[127.0.0.1]",
		"a@127.0.0.1",
		"a@0x7f.1",
		"a\u200Bb@example.com",
		"a@exa\nmple.com",
		"a@user:pass@example.com",
		"a@example.com?x=1",
		"a@example.com#x",
		"a@example.com\\x",
	]) {
		const factor: Factor = {
			id: "test-factor",
			strength: "possession",
			verify: async () =>
				succeed({
					provider: "email",
					externalId: email,
					email,
					emailVerified: true,
				}),
		};

		expect((await verifyProof(factor, undefined)).ok, email).toBe(false);
	}
});

test("A5: the same identity in two tenants is one account with a subject in each", async () => {
	const accounts = await createAccounts(["t1", "t2"]);
	const first = await resolve(
		accounts,
		"t1",
		await emailProof("a@example.com", true),
	);
	const second = await resolve(
		accounts,
		"t2",
		await emailProof("a@example.com", true),
	);

	expect(first.ok && first.value.identity).toBe("created");
	expect(second.ok && second.value.identity).toBe("existing");
	expect(second.ok && second.value.membership).toBe("created");
	expect(accountOf(first)).toBe(accountOf(second));
	expect(first.ok && first.value.subjectId).not.toBe(
		second.ok && second.value.subjectId,
	);
});

test("A5: tenant ids cannot collide through separators", async () => {
	const accounts = await createAccounts(['a","b', "a"]);
	const proof = await proveClaims({
		provider: "p",
		externalId: "c",
		emailVerified: false,
	});
	const first = await resolve(accounts, 'a","b', proof);
	const second = await resolve(accounts, "a", proof);

	expect(accountOf(first)).toBe(accountOf(second));
	expect(first.ok && first.value.subjectId).not.toBe(
		second.ok && second.value.subjectId,
	);
});

test("only a proof minted by verifyProof is planned", async () => {
	const accounts = await createAccounts(["t1"]);
	const options = optionsOf(accounts);

	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.anything(), async (forged) => {
			expect((await planSignIn(options, "t1", forged)).ok).toBe(false);
		}),
	);

	const lookAlike = {
		factor: "test-factor",
		strength: "possession",
		verifiedAtMilliseconds: 0,
		claims: {
			provider: "email",
			externalId: "a@example.com",
			email: "a@example.com",
			emailVerified: true,
		},
	};

	expect(await planSignIn(options, "t1", lookAlike)).toEqual({
		ok: false,
		error: "no-proof",
	});
});

test("concurrent first sign-ins of one identity create one account", async () => {
	const accounts = await createAccounts(["t1"]);
	const proof = await emailProof("a@example.com", true);

	const results = await Promise.all(
		Array.from({ length: 20 }, () => resolve(accounts, "t1", proof)),
	);
	const created = results.filter((result) => result.ok);
	const owner = await accounts.store.findIdentity("email", "a@example.com");

	expect(created.length).toBeGreaterThanOrEqual(1);
	expect(new Set(created.map((result) => accountOf(result)))).toEqual(
		new Set([owner?.accountId]),
	);
	expect(
		results.every((result) => result.ok || result.error === "conflict"),
	).toBe(true);
});

test("A4: a canonical address is frozen and lower case", () => {
	const canonical = canonicalizeEmail(" A@Example.com ");

	expect(canonical?.address).toBe("a@example.com");
	expect(canonical && Object.isFrozen(canonical)).toBe(true);
});

test("A4: length limits and the domain case mapping follow the standards", async () => {
	const accepted = (email: string) => canonicalizeEmail(email)?.address;

	expect(accepted(`${"a".repeat(64)}@example.com`)).toBe(
		`${"a".repeat(64)}@example.com`,
	);
	expect(accepted(`${"a".repeat(65)}@example.com`)).toBeUndefined();
	expect(accepted(`a@${"b".repeat(63)}.com`)).toBe(`a@${"b".repeat(63)}.com`);
	expect(accepted(`a@${"b".repeat(64)}.com`)).toBeUndefined();
	expect(
		accepted(
			`a@${["c".repeat(60), "c".repeat(60), "c".repeat(60), "c".repeat(60), "c".repeat(60), "com"].join(".")}`,
		),
	).toBeUndefined();
	expect(
		accepted(
			`${"a".repeat(64)}@${["d".repeat(60), "d".repeat(60), "d".repeat(60), "d".repeat(60), "com"].join(".")}`,
		),
	).toBeUndefined();
	expect(accepted(`a@${"e".repeat(2_000)}.com`)).toBeUndefined();
	expect(accepted("a@example.com.")).toBeUndefined();
	expect(accepted("a@example..com")).toBeUndefined();
	expect(accepted('"a b"@example.com')).toBeUndefined();
	expect(accepted("a(comment)@example.com")).toBeUndefined();
	expect(accepted("a@x.ΟΔΟΣ")).toBe(accepted("a@x.οδοσ"));
	expect(accepted("a@x.ΟΔΟΣ")).toBeDefined();
	expect(accepted("a@BÜCHER.example")).toBe(accepted("a@bücher.example"));
});
