import {
	createMemoryAccountStore,
	createMemoryEpochStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AuditRecord,
	createAuth,
	type Factor,
	fail,
	requireFactor,
	type SignInPolicyInput,
	succeed,
} from "@vow-auth/core";
import { createRecordSeal, createRecords } from "@vow-auth/core/internal";
import { factorPluginOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const MINUTE = 60_000;
const STEP_UP_LIFE = 5 * MINUTE;
const GOOD_CODE = "424242";
const SECRETS = [{ version: 1, value: "step-up-secret-0123456789abcdefghijk" }];

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const emailFactor: Factor = {
	id: "email",
	strength: "possession",
	verify: async (response) => {
		const address =
			typeof response === "object" && response !== null
				? Reflect.get(response, "email")
				: undefined;

		return typeof address === "string"
			? succeed({
					provider: "email",
					externalId: address,
					email: address,
					emailVerified: true,
				})
			: fail("invalid-proof");
	},
};

const totpFactor: Factor = {
	id: "totp",
	strength: "possession",
	verify: async (response) => {
		const code =
			typeof response === "object" && response !== null
				? Reflect.get(response, "code")
				: undefined;
		const user =
			typeof response === "object" && response !== null
				? Reflect.get(response, "user")
				: undefined;

		return code === GOOD_CODE && typeof user === "string"
			? succeed({
					provider: "totp",
					externalId: user,
					emailVerified: false,
				})
			: fail("invalid-proof");
	},
};

type Options = {
	readonly stepUpTimeToLiveMilliseconds?: number | undefined;
	readonly policy?: (input: SignInPolicyInput) => unknown;
};

const createFixture = async (options: Options = {}) => {
	const accounts = createMemoryAccountStore();
	const sealed = createRecords(createRecordSeal({ secrets: SECRETS }));
	const records: AuditRecord[] = [];
	const seen: SignInPolicyInput[] = [];
	const contexts: unknown[] = [];
	const watched =
		(factor: Factor): Factor["verify"] =>
		(response, context) => {
			contexts.push(context);

			return factor.verify(response, context);
		};
	const protectedSubjects = new Set<string>();
	const auth = createAuth({
		factors: {
			email: factorPluginOf(watched(emailFactor), { providers: ["email"] }),
			totp: factorPluginOf(watched(totpFactor), { providers: ["totp"] }),
		},
		accounts,
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: SECRETS,
		maximumLifeTimeMilliseconds: 60 * MINUTE,
		sessionTimeToLiveMilliseconds: 30 * MINUTE,
		stepUpTimeToLiveMilliseconds:
			"stepUpTimeToLiveMilliseconds" in options
				? options.stepUpTimeToLiveMilliseconds
				: STEP_UP_LIFE,
		registration: () => "allow",
		policy:
			options.policy ??
			((input) => {
				seen.push(input);

				const passedTotp = input.proofs.some(
					(proof) => proof.factor === "totp",
				);

				return protectedSubjects.has(input.subject) && !passedTotp
					? requireFactor("totp")
					: "allow";
			}),
		audit: async (record) => {
			records.push(record);
		},
	});

	const enroll = async (user: string, address: string, tenant = "acme") => {
		const first = await auth.signIn({
			tenant,
			device: "enrolling",
			factor: "email",
			response: { email: address },
		});

		if (!first.ok) {
			throw new Error("the first sign in must pass");
		}

		await accounts.linkIdentity(
			await sealed.identity({
				provider: "totp",
				externalId: user,
				accountId: first.value.account,
				email: undefined,
				emailVerified: false,
			}),
		);
		protectedSubjects.add(first.value.subject);

		return first.value;
	};

	await auth.tenants.create("acme");
	await auth.tenants.create("globex");

	return { auth, accounts, contexts, records, seen, enroll };
};

const stepUpOf = (result: {
	readonly ok: boolean;
	readonly error?: unknown;
}): { factor: string; continuation: string } => {
	const { error } = result;

	if (
		result.ok ||
		typeof error !== "object" ||
		error === null ||
		Reflect.get(error, "code") !== "step-up-required"
	) {
		throw new Error("a step-up was expected");
	}

	return {
		factor: String(Reflect.get(error, "factor")),
		continuation: String(Reflect.get(error, "continuation")),
	};
};

const firstStep = (
	auth: Awaited<ReturnType<typeof createFixture>>["auth"],
	address = "alice@example.com",
) =>
	auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "email",
		response: { email: address },
	});

test("A2: a policy that asks for another factor gets a challenge and no session", async () => {
	const { auth, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");

	const result = await firstStep(auth);

	expect(result.ok).toBe(false);
	expect(stepUpOf(result).factor).toBe("totp");
	expect(stepUpOf(result).continuation.length).toBeGreaterThan(20);
	expect(JSON.stringify(result)).not.toContain("token");
});

test("A2: the second factor completes the sign in, and the policy sees every proof", async () => {
	const { auth, seen, enroll } = await createFixture();
	const { subject } = await enroll("alice-totp", "alice@example.com");

	seen.length = 0;

	const challenge = stepUpOf(await firstStep(auth));
	const done = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "alice-totp", code: GOOD_CODE },
		continuation: challenge.continuation,
	});

	expect(done.ok && done.value.subject).toBe(subject);
	expect(done.ok && done.value.identity).toBe("existing");
	expect(done.ok && done.value.email).toBe("alice@example.com");
	expect(
		seen.map((input) => input.proofs.map((proof) => proof.factor)),
	).toEqual([["email"], ["email", "totp"]]);
	expect(seen[1]?.proof.factor).toBe("totp");
});

test("A2: the session records the factors that were passed and when, and the age grows", async () => {
	const { auth, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");

	const challenge = stepUpOf(await firstStep(auth));
	const done = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "alice-totp", code: GOOD_CODE },
		continuation: challenge.continuation,
	});

	if (!done.ok) {
		throw new Error("the second step must pass");
	}

	const signedInAt = Date.now();
	const fresh = await auth.sessions.verify(done.value.token);

	expect(fresh.ok && fresh.value).toMatchObject({
		methods: ["email", "totp"],
		authenticatedAtMilliseconds: signedInAt,
		authenticationAgeMilliseconds: 0,
	});

	vi.setSystemTime(signedInAt + 7 * MINUTE);

	const older = await auth.sessions.verify(done.value.token);

	expect(older.ok && older.value.authenticationAgeMilliseconds).toBe(
		7 * MINUTE,
	);
	expect(older.ok && older.value.authenticatedAtMilliseconds).toBe(signedInAt);
});

test("A2: a session that needed only one factor records only that one", async () => {
	const { auth } = await createFixture();
	const done = await firstStep(auth, "bob@example.com");

	if (!done.ok) {
		throw new Error("a person with no second factor signs in at once");
	}

	const verified = await auth.sessions.verify(done.value.token);

	expect(verified.ok && verified.value.methods).toEqual(["email"]);
});

test("A2: a continuation is spent by the first try, so a wrong code burns it", async () => {
	const { auth, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");

	const { continuation } = stepUpOf(await firstStep(auth));
	const wrong = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "alice-totp", code: "000000" },
		continuation,
	});
	const retry = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "alice-totp", code: GOOD_CODE },
		continuation,
	});

	expect(wrong).toEqual({ ok: false, error: "invalid-proof" });
	expect(retry).toEqual({ ok: false, error: "invalid-token" });
});

test("A2: a continuation cannot be used twice, also not at the same moment", async () => {
	const { auth, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");

	const { continuation } = stepUpOf(await firstStep(auth));
	const attempts = await Promise.all(
		Array.from({ length: 8 }, () =>
			auth.signIn({
				tenant: "acme",
				device: "laptop",
				factor: "totp",
				response: { user: "alice-totp", code: GOOD_CODE },
				continuation,
			}),
		),
	);

	expect(attempts.filter((attempt) => attempt.ok)).toHaveLength(1);
});

test("A2: a continuation expires", async () => {
	const { auth, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");

	const { continuation } = stepUpOf(await firstStep(auth));

	vi.setSystemTime(Date.now() + STEP_UP_LIFE + 1);

	expect(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "totp",
			response: { user: "alice-totp", code: GOOD_CODE },
			continuation,
		}),
	).toEqual({ ok: false, error: "invalid-token" });
});

test("A2: a continuation belongs to its tenant, device and factor, and is burned by a mismatch", async () => {
	const { auth, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");

	const mismatches = [
		{ tenant: "globex", device: "laptop", factor: "totp" },
		{ tenant: "acme", device: "phone", factor: "totp" },
		{ tenant: "acme", device: "laptop", factor: "email" },
	];

	for (const mismatch of mismatches) {
		const { continuation } = stepUpOf(await firstStep(auth));
		const refused = await auth.signIn({
			...mismatch,
			response: {
				user: "alice-totp",
				code: GOOD_CODE,
				email: "alice@example.com",
			},
			continuation,
		});
		const again = await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "totp",
			response: { user: "alice-totp", code: GOOD_CODE },
			continuation,
		});

		expect(refused.ok, JSON.stringify(mismatch)).toBe(false);
		expect(again).toEqual({ ok: false, error: "invalid-token" });
	}
});

test("A2: the second factor must belong to the same subject, and an unknown one creates nothing", async () => {
	const { auth, accounts, records, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");
	await enroll("bob-totp", "bob@example.com");

	const { continuation } = stepUpOf(await firstStep(auth));
	const crossed = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "bob-totp", code: GOOD_CODE },
		continuation,
	});

	expect(crossed).toEqual({ ok: false, error: "invalid-proof" });
	expect(records.at(-1)).toMatchObject({
		event: "signin.continue",
		outcome: "refusal",
		reason: "not-owner",
	});

	const second = stepUpOf(await firstStep(auth));
	const stranger = await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "mallory-totp", code: GOOD_CODE },
		continuation: second.continuation,
	});

	expect(stranger).toEqual({ ok: false, error: "invalid-proof" });
	expect(await accounts.findIdentity("totp", "mallory-totp")).toBe(undefined);
});

test("A2: a policy that asks again for a factor already passed ends the sign in", async () => {
	const { auth, enroll } = await createFixture({
		policy: () => requireFactor("email"),
	});

	void enroll;

	expect(await firstStep(auth)).toEqual({ ok: false, error: "no-allow" });
});

test("A2: without a step-up time the policy cannot ask, and the audit says why", async () => {
	const { auth, records } = await createFixture({
		stepUpTimeToLiveMilliseconds: undefined,
		policy: () => requireFactor("totp"),
	});

	expect(await firstStep(auth)).toEqual({ ok: false, error: "no-allow" });
	expect(
		records.find(
			(record) =>
				record.event === "policy.evaluate" &&
				record.detail.policy === "sign-in",
		),
	).toMatchObject({
		outcome: "refusal",
		reason: "step-up-unavailable",
	});
});

test("A2: only requireFactor can ask; a look-alike is an ordinary deny", async () => {
	const { auth } = await createFixture({
		policy: () => ({ kind: "step-up", factor: "totp" }),
	});

	expect(await firstStep(auth)).toEqual({ ok: false, error: "no-allow" });
});

test("A2: asking for no factor is a deny, never a half-open door", async () => {
	const { auth } = await createFixture({ policy: () => requireFactor("") });

	expect(await firstStep(auth)).toEqual({ ok: false, error: "no-allow" });
});

test("A2: the step-up is audited as a refusal with the factor asked for", async () => {
	const { auth, records, enroll } = await createFixture();

	await enroll("alice-totp", "alice@example.com");
	records.length = 0;
	await firstStep(auth);

	expect(
		records.filter((record) => record.event === "policy.evaluate"),
	).toEqual([
		expect.objectContaining({
			outcome: "refusal",
			reason: "step-up",
			detail: { policy: "sign-in", factor: "totp" },
		}),
	]);
	expect(records.map((record) => record.event)).not.toContain("session.issue");
});

test("A2: a request that carries an empty or non-text continuation is refused at once", async () => {
	const { auth } = await createFixture();

	for (const continuation of ["", 5, null, {}]) {
		expect(
			await auth.signIn({
				tenant: "acme",
				device: "laptop",
				factor: "totp",
				response: { user: "alice-totp", code: GOOD_CODE },
				// @ts-expect-error a continuation that is not text
				continuation,
			}),
		).toEqual({ ok: false, error: "invalid-request" });
	}
});

test("A2: a step-up time that is not a positive number stops the start", async () => {
	for (const stepUpTimeToLiveMilliseconds of [0, -1, Number.NaN]) {
		await expect(
			createFixture({ stepUpTimeToLiveMilliseconds }),
		).rejects.toThrow(RangeError);
	}
});

test("A2: the second step must use the factor that was asked for, not the first one again", async () => {
	const { auth } = await createFixture({
		policy: (input) =>
			input.proofs.length >= 2 ? "allow" : requireFactor("totp"),
	});
	const { continuation } = stepUpOf(await firstStep(auth));

	expect(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email",
			response: { email: "alice@example.com" },
			continuation,
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
});

test("the first step gives a factor the tenant and nothing else, the second the account and the proofs so far", async () => {
	const { auth, contexts, enroll } = await createFixture();
	const { account } = await enroll("alice-totp", "alice@example.com");

	contexts.length = 0;
	const challenge = stepUpOf(
		await auth.signIn({
			tenant: "acme",
			device: "laptop",
			factor: "email",
			response: { email: "alice@example.com" },
		}),
	);

	await auth.signIn({
		tenant: "acme",
		device: "laptop",
		factor: "totp",
		response: { user: "alice-totp", code: GOOD_CODE },
		continuation: challenge.continuation,
	});

	expect(contexts).toEqual([
		{ tenant: "acme", proofs: [] },
		{
			tenant: "acme",
			account,
			proofs: [expect.objectContaining({ factor: "email" })],
		},
	]);
});
