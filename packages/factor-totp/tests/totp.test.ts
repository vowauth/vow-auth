import {
	createMemoryAccountStore,
	createMemoryEpochStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	createAuth,
	defineDuration,
	type Factor,
	fail,
	requireFactor,
	succeed,
} from "@vow-auth/core";
import {
	createMemoryTotpStore,
	createTotp,
	type TotpLimitInput,
	type TotpOptions,
} from "@vow-auth/factor-totp";
import { factorPluginOf, meterRuleOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { decodeBase32 } from "../src/base32.js";
import { generateCode, stepOf } from "../src/otp.js";

const TENANT = "acme";
const START = 1_111_111_111_000;
const STEP_MILLISECONDS = 30_000;
const SECRET_LIFE = 365 * 24 * 60 * 60 * 1_000;

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(START);
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

const secretLife = () => {
	const life = defineDuration(SECRET_LIFE);

	if (!life.ok) {
		throw new Error("the life of a secret must be valid");
	}

	return life.value;
};

const createFixture = (overrides: Partial<TotpOptions> = {}) => {
	const enrolled = new Set<string>();
	const store = createMemoryTotpStore({ maximumRecords: 100 });
	const auth = createAuth({
		factors: {
			email: factorPluginOf(emailFactor.verify, { providers: ["email"] }),
			totp: createTotp({
				store,
				issuer: "Vow",
				secretTimeToLive: secretLife(),
				limit: "off",
				...overrides,
			}),
		},
		accounts: createMemoryAccountStore(),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: "totp-seal-0123456789abcdefghijklmnopq" }],
		maximumLifeTimeMilliseconds: 3_600_000,
		sessionTimeToLiveMilliseconds: 1_800_000,
		stepUpTimeToLiveMilliseconds: 300_000,
		registration: () => "allow",
		policy: ({ account, proofs }) =>
			enrolled.has(account) && !proofs.some((proof) => proof.factor === "totp")
				? requireFactor("totp")
				: "allow",
		audit: async () => undefined,
	});
	const totp = auth.factors.totp;

	const firstStep = async (address: string, device = "laptop") => {
		await auth.tenants.create(TENANT);

		return auth.signIn({
			tenant: TENANT,
			device,
			factor: "email",
			response: { email: address },
		});
	};

	const accountOf = async (address: string) => {
		const first = await firstStep(address);

		if (!first.ok) {
			throw new Error("the first sign in must pass");
		}

		return first.value.account;
	};

	const enroll = async (address: string) => {
		const account = await accountOf(address);
		const begun = await totp.begin({
			account,
			label: address,
		});

		if (!begun.ok) {
			throw new Error("begin must pass");
		}

		const secret = decodeBase32(begun.value.secret);

		if (secret === undefined) {
			throw new Error("the secret must be base32");
		}

		const confirmed = await totp.confirm({
			account,
			code: await generateCode(secret, stepOf(Date.now())),
		});

		if (!confirmed.ok) {
			throw new Error("confirm must pass");
		}

		enrolled.add(account);
		vi.setSystemTime(Date.now() + STEP_MILLISECONDS);

		return { account, secret, backupCodes: confirmed.value };
	};

	const challengeFor = async (address: string, device = "laptop") => {
		const result = await firstStep(address, device);

		if (result.ok || typeof result.error === "string") {
			throw new Error("a step-up was expected");
		}

		return result.error.continuation;
	};

	const secondStep = (
		continuation: string,
		response: unknown,
		device = "laptop",
	) =>
		auth.signIn({
			tenant: TENANT,
			device,
			factor: "totp",
			response,
			continuation,
		});

	return {
		auth,
		enrolled,
		store,
		totp,
		enroll,
		challengeFor,
		secondStep,
		accountOf,
		codeAt: (secret: Uint8Array<ArrayBuffer>, offsetSteps = 0) =>
			generateCode(secret, stepOf(Date.now()) + offsetSteps),
	};
};

test("an enrollment gives the secret and the address a QR code carries, and the store never holds the secret in the clear", async () => {
	const { totp, store, accountOf } = createFixture();
	const account = await accountOf("a@x.test");
	const begun = await totp.begin({
		account,
		label: "a@x.test",
	});

	expect(begun.ok).toBe(true);

	if (!begun.ok) {
		return;
	}

	expect(begun.value.secret).toMatch(/^[A-Z2-7]{32}$/);

	const uri = new URL(begun.value.uri);

	expect(uri.protocol).toBe("otpauth:");
	expect(uri.hostname).toBe("totp");
	expect(decodeURIComponent(uri.pathname)).toBe("/Vow:a@x.test");
	expect(Object.fromEntries(uri.searchParams)).toEqual({
		secret: begun.value.secret,
		issuer: "Vow",
		algorithm: "SHA1",
		digits: "6",
		period: "30",
	});

	const record = await store.find(account);

	expect(record?.confirmed).toBe(false);
	expect(JSON.stringify(record)).not.toContain(begun.value.secret);
});

test("an account or an issuer that would break the address is refused", async () => {
	const { totp, accountOf } = createFixture();
	const account = await accountOf("a@x.test");

	expect(await totp.begin({ account, label: "" })).toEqual({
		ok: false,
		error: "invalid-request",
	});

	const tricky = await totp.begin({
		account,
		label: "a b&secret=evil#:x",
	});

	expect(
		tricky.ok && new URL(tricky.value.uri).searchParams.get("secret"),
	).toBe(tricky.ok ? tricky.value.secret : "");

	for (const issuer of ["", "a:b"]) {
		expect(() =>
			createTotp({
				store: createMemoryTotpStore({ maximumRecords: 1 }),
				issuer,
				secretTimeToLive: secretLife(),
				limit: "off",
			}),
		).toThrow(RangeError);
	}
});

test("a first code that is wrong leaves the enrollment unconfirmed, a right one confirms it and shows ten backup codes once", async () => {
	const { totp, accountOf, store, codeAt } = createFixture();
	const account = await accountOf("a@x.test");
	const begun = await totp.begin({
		account,
		label: "a@x.test",
	});
	const secret = decodeBase32(begun.ok ? begun.value.secret : "");

	if (secret === undefined) {
		throw new Error("the secret must be base32");
	}

	expect(await totp.confirm({ account, code: "000000" })).toEqual({
		ok: false,
		error: "invalid-proof",
	});
	expect((await store.find(account))?.confirmed).toBe(false);

	const confirmed = await totp.confirm({
		account,
		code: await codeAt(secret),
	});

	expect(confirmed.ok && confirmed.value).toHaveLength(10);
	expect(
		confirmed.ok &&
			confirmed.value.every((code) =>
				/^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/.test(code),
			),
	).toBe(true);
	expect(new Set(confirmed.ok ? confirmed.value : []).size).toBe(10);
	expect((await store.find(account))?.confirmed).toBe(true);

	expect(await totp.confirm({ account, code: await codeAt(secret) })).toEqual({
		ok: false,
		error: "invalid-request",
	});
	expect(await totp.begin({ account, label: "a@x.test" })).toEqual({
		ok: false,
		error: "forbidden",
	});
});

test("the code that confirmed an enrollment cannot sign anyone in afterwards", async () => {
	const { enroll, challengeFor, secondStep, codeAt, store } = createFixture();
	const { account, secret } = await enroll("a@x.test");

	vi.setSystemTime(Date.now() - STEP_MILLISECONDS);

	const replayed = await codeAt(secret);
	const continuation = await challengeFor("a@x.test");

	expect((await secondStep(continuation, { code: replayed })).ok).toBe(false);
	expect((await store.find(account))?.lastStep).toBe(stepOf(Date.now()));
});

test("a step-up with the right code signs in, and the session remembers both factors", async () => {
	const { enroll, challengeFor, secondStep, codeAt, auth } = createFixture();
	const { account, secret } = await enroll("a@x.test");
	const continuation = await challengeFor("a@x.test");
	const done = await secondStep(continuation, { code: await codeAt(secret) });

	expect(done.ok && done.value.account).toBe(account);

	const session = done.ok
		? await auth.sessions.verify(done.value.token)
		: undefined;

	expect(session?.ok && session.value.methods).toEqual(["email", "totp"]);
});

test("a code is accepted once: the same code, or an older one, is refused", async () => {
	const { enroll, challengeFor, secondStep, codeAt } = createFixture();
	const { secret } = await enroll("a@x.test");
	const code = await codeAt(secret);

	expect((await secondStep(await challengeFor("a@x.test"), { code })).ok).toBe(
		true,
	);
	expect((await secondStep(await challengeFor("a@x.test"), { code })).ok).toBe(
		false,
	);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				code: await codeAt(secret, -1),
			})
		).ok,
	).toBe(false);

	vi.setSystemTime(Date.now() + STEP_MILLISECONDS);

	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				code: await codeAt(secret),
			})
		).ok,
	).toBe(true);
});

test("one step of drift either way is accepted, two are not", async () => {
	const { enroll, challengeFor, secondStep, codeAt } = createFixture();
	const { secret } = await enroll("a@x.test");

	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				code: await codeAt(secret, -2),
			})
		).ok,
	).toBe(false);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				code: await codeAt(secret, 2),
			})
		).ok,
	).toBe(false);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				code: await codeAt(secret, 1),
			})
		).ok,
	).toBe(true);
});

test("a wrong code, a missing one and a code of another type are all the same refusal", async () => {
	const { enroll, challengeFor, secondStep } = createFixture();

	await enroll("a@x.test");

	for (const response of [
		{ code: "000000" },
		{ code: 123456 },
		{ code: null },
		{},
		"123456",
		null,
		undefined,
		{ backupCode: 7 },
	]) {
		expect(
			await secondStep(await challengeFor("a@x.test"), response),
			JSON.stringify(response),
		).toEqual({ ok: false, error: "invalid-proof" });
	}
});

test("a backup code works once, whatever its case, spaces and dashes", async () => {
	const { enroll, challengeFor, secondStep } = createFixture();
	const { backupCodes } = await enroll("a@x.test");
	const [first = "", second = ""] = backupCodes;
	const loose = first.toLowerCase().replaceAll("-", " ");

	expect(
		(await secondStep(await challengeFor("a@x.test"), { backupCode: loose }))
			.ok,
	).toBe(true);
	expect(
		(await secondStep(await challengeFor("a@x.test"), { backupCode: first }))
			.ok,
	).toBe(false);
	expect(
		(await secondStep(await challengeFor("a@x.test"), { backupCode: second }))
			.ok,
	).toBe(true);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				backupCode: "AAAA-AAAA",
			})
		).ok,
	).toBe(false);
});

test("new backup codes replace the old ones", async () => {
	const { enroll, challengeFor, secondStep, totp } = createFixture();
	const { account, backupCodes } = await enroll("a@x.test");
	const renewed = await totp.renewBackupCodes({ account });

	expect(renewed.ok && renewed.value).toHaveLength(10);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				backupCode: backupCodes[0],
			})
		).ok,
	).toBe(false);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				backupCode: renewed.ok ? renewed.value[0] : "",
			})
		).ok,
	).toBe(true);
	expect(await totp.renewBackupCodes({ account: "nobody" })).toEqual({
		ok: false,
		error: "invalid-request",
	});
});

test("a code of one person does not sign another in", async () => {
	const { enroll, challengeFor, secondStep, codeAt } = createFixture();
	const alice = await enroll("a@x.test");
	const bob = await enroll("b@x.test");

	expect(alice.account).not.toBe(bob.account);
	expect(
		(
			await secondStep(await challengeFor("b@x.test"), {
				code: await codeAt(alice.secret),
			})
		).ok,
	).toBe(false);
	expect(
		(
			await secondStep(await challengeFor("b@x.test"), {
				backupCode: alice.backupCodes[0],
			})
		).ok,
	).toBe(false);
	expect(
		(
			await secondStep(await challengeFor("b@x.test"), {
				code: await codeAt(bob.secret),
			})
		).ok,
	).toBe(true);
});

test("a sealed secret copied to another account does not open", async () => {
	const {
		enroll,
		challengeFor,
		secondStep,
		codeAt,
		store,
		accountOf,
		enrolled,
	} = createFixture();
	const alice = await enroll("a@x.test");
	const bobAccount = await accountOf("b@x.test");
	const record = await store.find(alice.account);

	if (record === undefined) {
		throw new Error("the record must exist");
	}

	await store.save(bobAccount, record);
	enrolled.add(bobAccount);

	const continuation = await challengeFor("b@x.test");

	expect(
		(await secondStep(continuation, { code: await codeAt(alice.secret) })).ok,
	).toBe(false);
});

test("the factor cannot be the first step: it does not say who the person is", async () => {
	const { auth, enroll, codeAt } = createFixture();
	const { secret } = await enroll("a@x.test");

	expect(
		await auth.signIn({
			tenant: TENANT,
			device: "laptop",
			factor: "totp",
			response: { code: await codeAt(secret) },
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
});

test("an account whose enrollment was never confirmed cannot pass with any code", async () => {
	const { totp, enrolled, accountOf, challengeFor, secondStep } =
		createFixture();
	const account = await accountOf("a@x.test");
	const begun = await totp.begin({
		account,
		label: "a@x.test",
	});
	const secret = decodeBase32(begun.ok ? begun.value.secret : "");

	enrolled.add(account);

	expect(secret).toBeDefined();
	expect(
		await secondStep(await challengeFor("a@x.test"), {
			code: await generateCode(secret ?? new Uint8Array(), stepOf(Date.now())),
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
});

test("removing an enrollment ends the factor for that account", async () => {
	const { enroll, challengeFor, secondStep, codeAt, totp } = createFixture();
	const { account, secret } = await enroll("a@x.test");

	expect(await totp.remove({ account })).toBe(true);
	expect(await totp.remove({ account })).toBe(false);
	expect(
		(
			await secondStep(await challengeFor("a@x.test"), {
				code: await codeAt(secret),
			})
		).ok,
	).toBe(false);
});

test("a limit stops guessing for one account and not for another", async () => {
	const { enroll, challengeFor, secondStep, codeAt } = createFixture({
		limit: {
			rule: meterRuleOf({ limit: 3, windowMilliseconds: 600_000 }),
			scopes: ({ account, action }: TotpLimitInput) => [
				{ tenant: TENANT, actor: account, resource: `totp:${action}` },
			],
		},
	});
	const alice = await enroll("a@x.test");
	const bob = await enroll("b@x.test");

	for (let attempt = 0; attempt < 3; attempt += 1) {
		expect(
			await secondStep(await challengeFor("a@x.test"), { code: "000000" }),
		).toEqual({ ok: false, error: "invalid-proof" });
	}

	expect(
		await secondStep(await challengeFor("a@x.test"), {
			code: await codeAt(alice.secret),
		}),
	).toEqual({ ok: false, error: "invalid-proof" });
	expect(
		(
			await secondStep(await challengeFor("b@x.test"), {
				code: await codeAt(bob.secret),
			})
		).ok,
	).toBe(true);
});

test("a limit that is forgotten stops the factor from being built", () => {
	for (const limit of [undefined, "none", 7]) {
		expect(() =>
			createTotp({
				store: createMemoryTotpStore({ maximumRecords: 1 }),
				issuer: "Vow",
				secretTimeToLive: secretLife(),
				// @ts-expect-error the point of the test is a value that is not a limit
				limit,
			}),
		).toThrow(TypeError);
	}
});

test("an enrollment belongs to the account, so it works in every tenant, and goes with the account", async () => {
	const { auth, enroll, codeAt, store } = createFixture();
	const { account, secret } = await enroll("a@x.test");

	await auth.tenants.create("globex");

	const first = await auth.signIn({
		tenant: "globex",
		device: "laptop",
		factor: "email",
		response: { email: "a@x.test" },
	});

	if (first.ok || typeof first.error === "string") {
		throw new Error("the account needs its second factor in every tenant");
	}

	const done = await auth.signIn({
		tenant: "globex",
		device: "laptop",
		factor: "totp",
		response: { code: await codeAt(secret) },
		continuation: first.error.continuation,
	});

	expect(done.ok && done.value.account).toBe(account);
	expect(done.ok && done.value.tenant).toBe("globex");
	expect(await store.find(account)).toBeDefined();
	expect((await auth.accounts.delete(account)).ok).toBe(true);
	expect(await store.find(account)).toBeUndefined();
});
