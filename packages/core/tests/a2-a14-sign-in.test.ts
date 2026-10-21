import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
} from "@vow-auth/adapter-memory";
import * as core from "@vow-auth/core";
import {
	type AuditRecord,
	createMutateIdentity,
	createSealer,
	createSessionTokens,
	createSignIn,
	type Factor,
	type ProofStrength,
	type SignInPolicyInput,
	succeed,
} from "@vow-auth/core/internal";
import { expect, test, vi } from "vitest";

const LIFE_TIME = 60_000;

const factorOf = (
	id: string,
	strength: ProofStrength,
	claims: unknown,
): Factor => ({
	id,
	strength,
	verify: async () => succeed(claims),
});

const emailClaims = (email: string, emailVerified = true) => ({
	provider: "email",
	externalId: email,
	email,
	emailVerified,
});

const createFixture = (options: {
	policy?: (input: SignInPolicyInput) => unknown;
	audit?: (record: AuditRecord) => Promise<void>;
}) => {
	const identities = createMemoryIdentityStore();
	const audit = options.audit;
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: "flow-secret-0123456789abcdefghijklmn" }],
		}),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		maximumLifeTimeMilliseconds: LIFE_TIME,
		audit,
	});
	const issueSpy = vi.spyOn(sessionTokens, "issue");
	const mutateIdentity = createMutateIdentity({
		store: identities,
		sessionTokens,
		audit,
	});
	const signIn = createSignIn({
		identities,
		sessionTokens,
		mutateIdentity,
		policy: options.policy ?? (() => "allow"),
		sessionTimeToLiveMilliseconds: LIFE_TIME,
		audit,
	});

	return { issueSpy, sessionTokens, signIn };
};

test("A14: the public API has no way to create a session or to build a part without the audit", () => {
	expect(Object.keys(core)).not.toContain("issueSession");
	expect(Object.keys(core)).toContain("createAuth");

	for (const building of [
		"isBornSession",
		"createSignIn",
		"createTokens",
		"createSealer",
		"createSessionTokens",
		"createMutateIdentity",
		"verifyProof",
		"resolveIdentity",
		"evaluatePolicy",
	]) {
		expect(Object.keys(core), building).not.toContain(building);
	}
	// @ts-expect-error a plugin importing the core cannot reach issueSession
	expect(core.issueSession).toBeUndefined();
});

test("A14: a session that was not born in the flow gets no token", async () => {
	const { sessionTokens } = createFixture({});
	const forged = await sessionTokens.issue(
		{ id: "s-1", subject: "admin" },
		{ tenant: "acme", device: "laptop", timeToLiveMilliseconds: LIFE_TIME },
	);

	expect(forged.ok).toBe(false);
});

test("A2: a factor nobody wrote a line for is under the same ban, whatever it is", async () => {
	const banned = new Set<string>();
	const { signIn } = createFixture({
		policy: ({ subject }) => (banned.has(subject) ? "deny" : "allow"),
	});
	const claims = emailClaims("alice@example.com");

	const first = await signIn({
		tenant: "acme",
		device: "laptop",
		factor: factorOf("first-factor", "possession", claims),
		response: undefined,
	});

	if (!first.ok) {
		throw new Error("the first sign in must pass");
	}

	banned.add(first.value.subject);

	for (const strength of ["possession", "knowledge", "inherence"] as const) {
		const result = await signIn({
			tenant: "acme",
			device: "phone",
			factor: factorOf(`brand-new-${strength}`, strength, claims),
			response: undefined,
		});

		expect(!result.ok && result.error, strength).toBe("no-allow");
	}
});

test("A2: the policy sees how the person proved themselves and can demand more", async () => {
	const seen: SignInPolicyInput[] = [];
	const { signIn } = createFixture({
		policy: (input) => {
			seen.push(input);

			return input.proof.strength === "possession" ? "allow" : "deny";
		},
	});
	const claims = emailClaims("alice@example.com");
	const strong = await signIn({
		tenant: "acme",
		device: "laptop",
		factor: factorOf("strong", "possession", claims),
		response: undefined,
	});
	const weak = await signIn({
		tenant: "acme",
		device: "laptop",
		factor: factorOf("weak", "knowledge", claims),
		response: undefined,
	});

	expect(strong.ok).toBe(true);
	expect(!weak.ok && weak.error).toBe("no-allow");
	expect(
		seen.map((input) => [
			input.tenant,
			input.proof.factor,
			input.proof.strength,
		]),
	).toEqual([
		["acme", "strong", "possession"],
		["acme", "weak", "knowledge"],
	]);
	expect(typeof seen[0]?.proof.verifiedAtMilliseconds).toBe("number");
});

test("A2: every step of every factor is audited", async () => {
	const records: AuditRecord[] = [];
	const { signIn } = createFixture({
		audit: async (record) => {
			records.push(record);
		},
	});

	await signIn({
		tenant: "acme",
		device: "laptop",
		factor: factorOf(
			"novel-factor",
			"possession",
			emailClaims("a@example.com"),
		),
		response: undefined,
	});

	expect(records.map((record) => `${record.event}:${record.reason}`)).toEqual([
		"proof.verify:verified",
		"identity.resolve:created",
		"identity.mutate:email-confirmed",
		"policy.evaluate:allow",
		"session.issue:issued",
	]);
	expect(records[0]?.detail.factor).toBe("novel-factor");
});

test("a verified email evicts earlier claims by itself, nobody has to remember to ask", async () => {
	const { sessionTokens, signIn } = createFixture({});
	const squatter = await signIn({
		tenant: "acme",
		device: "phone",
		factor: factorOf("evil", "possession", {
			provider: "evil",
			externalId: "e-1",
			email: "victim@example.com",
			emailVerified: false,
		}),
		response: undefined,
	});
	const victim = await signIn({
		tenant: "acme",
		device: "laptop",
		factor: factorOf("email", "possession", emailClaims("victim@example.com")),
		response: undefined,
	});

	if (!squatter.ok || !victim.ok) {
		throw new Error("both sign ins must pass");
	}

	expect(victim.value.evicted).toEqual([squatter.value.subject]);
	expect((await sessionTokens.verify(squatter.value.token)).ok).toBe(false);
	expect((await sessionTokens.verify(victim.value.token)).ok).toBe(true);
});

test("a refusal reports the step that refused and issues nothing", async () => {
	const { issueSpy, signIn } = createFixture({ policy: () => "deny" });
	const run = (tenant: string, factor: Factor) =>
		signIn({ tenant, device: "laptop", factor, response: undefined });

	const results = [
		await run("", factorOf("f", "possession", emailClaims("a@example.com"))),
		await run("acme", factorOf("f", "possession", { provider: "p" })),
		await run(
			"acme",
			factorOf("f", "possession", emailClaims("a@example.com")),
		),
	];

	expect(results.map((result) => !result.ok && result.error)).toEqual([
		"invalid-request",
		"invalid-proof",
		"no-allow",
	]);
	expect(issueSpy).not.toHaveBeenCalled();
});

test("a failing audit means no session", async () => {
	const { issueSpy, signIn } = createFixture({
		audit: async () => {
			throw new Error("the audit store is down");
		},
	});

	await expect(
		signIn({
			tenant: "acme",
			device: "laptop",
			factor: factorOf("f", "possession", emailClaims("a@example.com")),
			response: undefined,
		}),
	).rejects.toThrow("the audit store is down");
	expect(issueSpy).not.toHaveBeenCalled();
});

test("when the email cannot be confirmed the policy is not even asked", async () => {
	const identities = createMemoryIdentityStore();
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: "flow-secret-0123456789abcdefghijklmn" }],
		}),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		maximumLifeTimeMilliseconds: LIFE_TIME,
	});
	const policy = vi.fn(() => "allow");
	const signIn = createSignIn({
		identities,
		sessionTokens,
		mutateIdentity: async () => ({ ok: false, error: "forbidden" }),
		policy,
		sessionTimeToLiveMilliseconds: LIFE_TIME,
	});

	const result = await signIn({
		tenant: "acme",
		device: "laptop",
		factor: factorOf("f", "possession", emailClaims("a@example.com")),
		response: undefined,
	});

	expect(!result.ok && result.error).toBe("forbidden");
	expect(policy).not.toHaveBeenCalled();
});
