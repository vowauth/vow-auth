import { createMemoryIdentityStore } from "@vow-auth/adapter-memory";
import {
	canonicalizeEmail,
	type Factor,
	resolveIdentity,
	succeed,
	verifyProof,
} from "@vow-auth/core/internal";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

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

test("the same identity resolves to the same subject", async () => {
	const store = createMemoryIdentityStore();

	const first = await resolveIdentity(
		store,
		"t1",
		await emailProof("a@example.com", true),
	);
	const second = await resolveIdentity(
		store,
		"t1",
		await emailProof("a@example.com", true),
	);

	expect(first.ok && first.value.outcome).toBe("created");
	expect(second.ok && second.value.outcome).toBe("existing");
	expect(first.ok && second.ok && first.value.subjectId).toBe(
		second.ok && second.value.subjectId,
	);
});

test("A3: a verified email links a new provider to the existing subject", async () => {
	const store = createMemoryIdentityStore();
	const created = await resolveIdentity(
		store,
		"t1",
		await emailProof("a@example.com", true),
	);
	const linked = await resolveIdentity(
		store,
		"t1",
		await googleProof("g-1", "a@example.com", true),
	);

	expect(linked.ok && linked.value.outcome).toBe("linked");
	expect(linked.ok && created.ok && linked.value.subjectId).toBe(
		created.ok && created.value.subjectId,
	);
});

test("A3: an unverified email never links to an existing subject", async () => {
	const store = createMemoryIdentityStore();
	const victim = await resolveIdentity(
		store,
		"t1",
		await emailProof("victim@example.com", true),
	);
	const attacker = await resolveIdentity(
		store,
		"t1",
		await googleProof("g-attacker", "victim@example.com", false),
	);

	expect(attacker.ok && attacker.value.outcome).toBe("created");
	expect(attacker.ok && victim.ok && attacker.value.subjectId).not.toBe(
		victim.ok && victim.value.subjectId,
	);
});

test("A3: a verified email does not link to a subject whose email was never verified", async () => {
	const store = createMemoryIdentityStore();
	const squatter = await resolveIdentity(
		store,
		"t1",
		await googleProof("g-squatter", "victim@example.com", false),
	);
	const victim = await resolveIdentity(
		store,
		"t1",
		await emailProof("victim@example.com", true),
	);

	expect(victim.ok && victim.value.outcome).toBe("created");
	expect(squatter.ok && victim.ok && victim.value.subjectId).not.toBe(
		squatter.ok && squatter.value.subjectId,
	);
});

test("A4: email spelling variants resolve to one subject", async () => {
	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.constantFrom(
				"alice@example.com",
				"ALICE@EXAMPLE.COM",
				"  Alice@Example.Com  ",
				"alice@EXAMPLE.com\t",
			),
			async (variant) => {
				const store = createMemoryIdentityStore();
				const reference = await resolveIdentity(
					store,
					"t1",
					await emailProof("alice@example.com", true),
				);
				const resolved = await resolveIdentity(
					store,
					"t1",
					await emailProof(variant, true),
				);

				expect(resolved.ok && resolved.value.subjectId).toBe(
					reference.ok && reference.value.subjectId,
				);
			},
		),
	);
});

test("A4: internationalized domains resolve to their punycode form", async () => {
	const store = createMemoryIdentityStore();
	const unicode = await resolveIdentity(
		store,
		"t1",
		await emailProof("a@bücher.example", true),
	);
	const punycode = await resolveIdentity(
		store,
		"t1",
		await emailProof("a@xn--bcher-kva.example", true),
	);

	expect(unicode.ok && unicode.value.subjectId).toBe(
		punycode.ok && punycode.value.subjectId,
	);
});

test("A4: letters of any script are allowed in the local part", async () => {
	const store = createMemoryIdentityStore();

	for (const email of ["bücher@example.com", "пользователь@example.com"]) {
		const result = await resolveIdentity(
			store,
			"t1",
			await emailProof(email, true),
		);

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

test("A5: the same identity in two tenants resolves to two subjects", async () => {
	const store = createMemoryIdentityStore();
	const first = await resolveIdentity(
		store,
		"t1",
		await emailProof("a@example.com", true),
	);
	const second = await resolveIdentity(
		store,
		"t2",
		await emailProof("a@example.com", true),
	);

	expect(first.ok && first.value.outcome).toBe("created");
	expect(second.ok && second.value.outcome).toBe("created");
	expect(first.ok && second.ok && first.value.subjectId).not.toBe(
		second.ok && second.value.subjectId,
	);
});

test("A5: a verified email does not link across tenants", async () => {
	const store = createMemoryIdentityStore();
	await resolveIdentity(store, "t1", await emailProof("a@example.com", true));
	const other = await resolveIdentity(
		store,
		"t2",
		await googleProof("g-1", "a@example.com", true),
	);

	expect(other.ok && other.value.outcome).toBe("created");
});

test("A5: tenant ids cannot collide through separators", async () => {
	const store = createMemoryIdentityStore();
	const first = await resolveIdentity(
		store,
		'a","b',
		await proveClaims({
			provider: "p",
			externalId: "c",
			emailVerified: false,
		}),
	);
	const second = await resolveIdentity(
		store,
		"a",
		await proveClaims({
			provider: 'b","p',
			externalId: "c",
			emailVerified: false,
		}),
	);

	expect(first.ok && second.ok && first.value.subjectId).not.toBe(
		second.ok && second.value.subjectId,
	);
});

test("only a proof minted by verifyProof resolves", async () => {
	const store = createMemoryIdentityStore();

	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.anything(), async (forged) => {
			expect((await resolveIdentity(store, "t1", forged)).ok).toBe(false);
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

	expect((await resolveIdentity(store, "t1", lookAlike)).ok).toBe(false);
});

test("concurrent first sign-ins of one identity create one subject", async () => {
	const store = createMemoryIdentityStore();
	const proof = await emailProof("a@example.com", true);

	const results = await Promise.all(
		Array.from({ length: 20 }, () => resolveIdentity(store, "t1", proof)),
	);
	const subjects = new Set(
		results.map((result) => result.ok && result.value.subjectId),
	);

	expect(subjects.size).toBe(1);
});

test("A4: the store takes only a canonical address, which the compiler enforces", async () => {
	const store = createMemoryIdentityStore();

	// @ts-expect-error a raw string is not a canonical email
	await store.findSubjectByVerifiedEmail("t1", "a@example.com");
	// @ts-expect-error an object that only looks like one is not a canonical email
	await store.findSubjectByVerifiedEmail("t1", { address: "a@example.com" });

	const canonical = canonicalizeEmail(" A@Example.com ");

	expect(canonical?.address).toBe("a@example.com");
	expect(canonical && Object.isFrozen(canonical)).toBe(true);
	expect(
		canonical && (await store.findSubjectByVerifiedEmail("t1", canonical)),
	).toBeUndefined();
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
