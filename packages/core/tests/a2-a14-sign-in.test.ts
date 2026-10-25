import {
	createMemoryGrantStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import * as core from "@vow-auth/core";
import {
	type AuditRecord,
	createGrants,
	createSignIn,
	createTokens,
	type Factor,
	type ProofStrength,
	type SignInPolicyInput,
	type SignInRequest,
	succeed,
} from "@vow-auth/core/internal";
import { expect, test, vi } from "vitest";
import { createAccounts } from "./support/accounts.js";

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

const createFixture = async (options: {
	policy?: (input: SignInPolicyInput) => unknown;
	audit?: (record: AuditRecord) => Promise<void>;
}) => {
	const accounts = await createAccounts();
	const audit = options.audit;
	const grants = createGrants({
		store: createMemoryGrantStore(),
		records: accounts.records,
		idleMilliseconds: LIFE_TIME,
		maximumMilliseconds: LIFE_TIME,
		audit,
	});
	const issueSpy = vi.spyOn(grants, "issue");
	const factors = new Map<string, Factor>();
	const signInById = createSignIn({
		factors,
		accounts: accounts.store,
		records: accounts.records,
		trustedProviders: ["email"],
		grants,
		tokens: createTokens({
			store: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		}),
		registration: () => "allow",
		policy: options.policy ?? (() => "allow"),
		audit,
	});
	const signIn = (
		request: Omit<SignInRequest, "factor"> & { readonly factor: Factor },
	) => {
		factors.set(request.factor.id, request.factor);

		return signInById({ ...request, factor: request.factor.id });
	};

	return { grants, issueSpy, signIn };
};

test("A14: the public API has no way to create a session or to build a part without the audit", () => {
	expect(Object.keys(core)).not.toContain("issueSession");
	expect(Object.keys(core)).toContain("createAuth");

	for (const building of [
		"isBornSession",
		"createSignIn",
		"createTokens",
		"createSealer",
		"createGrants",
		"createRecordSeal",
		"createRecords",
		"createManagement",
		"verifyProof",
		"planSignIn",
		"applyPlan",
		"evaluatePolicy",
	]) {
		expect(Object.keys(core), building).not.toContain(building);
	}
	// @ts-expect-error a plugin importing the core cannot reach issueSession
	expect(core.issueSession).toBeUndefined();
});

test("A14: a session that was not born in the flow gets no token", async () => {
	const { grants } = await createFixture({});
	const forged = await grants.issue(
		{ id: "s-1", subject: "admin" },
		{
			accountId: "acc_admin",
			tenant: "acme",
			subjectId: "admin",
			device: "laptop",
			proofs: [],
		},
	);

	expect(forged.ok).toBe(false);
});

test("A2: a factor nobody wrote a line for is under the same ban, whatever it is", async () => {
	const banned = new Set<string>();
	const { signIn } = await createFixture({
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
	const { signIn } = await createFixture({
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
	const { signIn } = await createFixture({
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
		"policy.evaluate:allow",
		"policy.evaluate:allow",
		"identity.resolve:created",
		"session.issue:issued",
	]);
	expect(
		records
			.filter((record) => record.event === "policy.evaluate")
			.map((record) => record.detail.policy),
	).toEqual(["registration", "sign-in"]);
	expect(records[0]?.detail.factor).toBe("novel-factor");
});

test("a verified email evicts earlier claims by itself, nobody has to remember to ask", async () => {
	const { grants, signIn } = await createFixture({});
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

	expect(victim.value.evicted).toEqual([squatter.value.account]);
	expect((await grants.verify(squatter.value.token, "acme")).ok).toBe(false);
	expect((await grants.verify(victim.value.token, "acme")).ok).toBe(true);
});

test("a refusal reports the step that refused and issues nothing", async () => {
	const { issueSpy, signIn } = await createFixture({ policy: () => "deny" });
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
	const { issueSpy, signIn } = await createFixture({
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

test("a tenant the application did not create is refused before any policy is asked", async () => {
	const policy = vi.fn(() => "allow");
	const { issueSpy, signIn } = await createFixture({ policy });

	const result = await signIn({
		tenant: "nowhere",
		device: "laptop",
		factor: factorOf("f", "possession", emailClaims("a@example.com")),
		response: undefined,
	});

	expect(!result.ok && result.error).toBe("no-tenant");
	expect(policy).not.toHaveBeenCalled();
	expect(issueSpy).not.toHaveBeenCalled();
});
