import {
	createMemoryAccountStore,
	createMemoryGrantStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AccountStore,
	type AuditRecord,
	type AuditSink,
	createAuth,
	createRecordSeal,
	createRecords,
	createSecretBox,
	createSigningKeys,
	type PrivateSigningJwk,
	type SecretVersion,
	type StoredSigningKey,
	succeed,
	type TenantSigningKey,
} from "@vow-auth/core/internal";
import { factorPluginOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const HOUR = 3_600_000;
const SECRET: SecretVersion = {
	version: 1,
	value: "signing-secret-0123456789abcdefghijk",
};
const NEW_SECRET: SecretVersion = {
	version: 2,
	value: "signing-secret-2-ABCDEFGHIJKLMNOPQRS",
};
const encoder = new TextEncoder();

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const later = (milliseconds: number) =>
	vi.setSystemTime(Date.now() + milliseconds);

/** The engine and the signing keys of its tenants on one store, as `createAuth` builds them. */
const createFixture = async (
	options: {
		readonly store?: AccountStore;
		readonly secrets?: readonly SecretVersion[];
		readonly audit?: AuditSink;
	} = {},
) => {
	const store = options.store ?? createMemoryAccountStore();
	const secrets = options.secrets ?? [SECRET];
	const audit = options.audit ?? (async () => undefined);
	const auth = createAuth({
		accounts: store,
		grants: createMemoryGrantStore(),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets,
		factors: {
			email: factorPluginOf(async (response) =>
				succeed({
					provider: "email",
					externalId: String(Reflect.get(Object(response), "email")),
					email: String(Reflect.get(Object(response), "email")),
					emailVerified: true,
				}),
			),
		},
		maximumLifeTimeMilliseconds: HOUR,
		sessionTimeToLiveMilliseconds: HOUR,
		signingKeyPropagationMilliseconds: HOUR,
		registration: () => "allow",
		policy: () => "allow",
		audit,
	});
	const records = createRecords(createRecordSeal({ secrets }));
	const keys = createSigningKeys({
		store,
		records,
		box: createSecretBox({ secrets }),
		propagationMilliseconds: HOUR,
		audit,
	});

	if (options.store === undefined) {
		expect((await auth.tenants.create("acme")).ok).toBe(true);
		expect((await auth.tenants.create("globex")).ok).toBe(true);
	}

	const signIn = (tenant: string) =>
		auth.signIn({
			tenant,
			device: "laptop",
			factor: "email",
			response: { email: "ivan@example.com" },
		});

	return { auth, keys, records, signIn, store };
};

const valueFrom = <Value>(result: {
	readonly ok: boolean;
	readonly value?: Value;
	readonly error?: unknown;
}): Value => {
	if (!result.ok || result.value === undefined) {
		throw new Error(`the call must pass: ${JSON.stringify(result)}`);
	}

	return result.value;
};

const kidIn = (
	keys: readonly TenantSigningKey[],
	state: TenantSigningKey["state"],
): string => {
	const key = keys.find((candidate) => candidate.state === state);

	if (key === undefined) {
		throw new Error(`a ${state} key must be listed`);
	}

	return key.kid;
};

const thumbprintOf = async (jwk: PrivateSigningJwk): Promise<string> =>
	Buffer.from(
		await crypto.subtle.digest(
			"SHA-256",
			encoder.encode(
				JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }),
			),
		),
	).toString("base64url");

const signsAndVerifies = async (jwk: PrivateSigningJwk): Promise<boolean> => {
	const algorithm = { name: "ECDSA", namedCurve: "P-256" };
	const signing = await crypto.subtle.importKey("jwk", jwk, algorithm, false, [
		"sign",
	]);
	const { d: _private, ...publicJwk } = jwk;
	const verifying = await crypto.subtle.importKey(
		"jwk",
		{ ...publicJwk, key_ops: ["verify"] },
		algorithm,
		false,
		["verify"],
	);
	const message = encoder.encode("a token");
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		signing,
		message,
	);

	return crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		verifying,
		signature,
		message,
	);
};

test("A33: the first rotation creates a current and a next key, and each later one lets the next key sign only after it was published for the propagation time", async () => {
	const { auth, store } = await createFixture();
	const first = valueFrom(await auth.tenants.rotateSigningKey("acme"));

	expect(first.map((key) => key.state).sort()).toEqual(["current", "next"]);
	expect(await auth.tenants.rotateSigningKey("acme")).toEqual({
		ok: false,
		error: "too-soon",
	});

	later(HOUR - 1);

	expect(await auth.tenants.rotateSigningKey("acme")).toEqual({
		ok: false,
		error: "too-soon",
	});

	later(1);

	const second = valueFrom(await auth.tenants.rotateSigningKey("acme"));

	expect(kidIn(second, "current")).toBe(kidIn(first, "next"));
	expect(kidIn(second, "previous")).toBe(kidIn(first, "current"));
	expect(first.map((key) => key.kid)).not.toContain(kidIn(second, "next"));

	later(HOUR);

	const third = valueFrom(await auth.tenants.rotateSigningKey("acme"));

	expect(kidIn(third, "current")).toBe(kidIn(second, "next"));
	expect(kidIn(third, "previous")).toBe(kidIn(second, "current"));
	expect(third.map((key) => key.kid)).not.toContain(kidIn(first, "current"));
	expect(third).toHaveLength(3);
	expect((await store.getTenant("acme"))?.signingKeys).toEqual(third);
	expect((await store.getTenant("globex"))?.signingKeys).toEqual([]);
});

test("A33: two rotations at once write one new key set, and the other is refused", async () => {
	const { auth, store } = await createFixture();
	const results = await Promise.all([
		auth.tenants.rotateSigningKey("acme"),
		auth.tenants.rotateSigningKey("acme"),
	]);

	expect(results.filter((result) => result.ok)).toHaveLength(1);
	expect(results.find((result) => !result.ok)).toEqual({
		ok: false,
		error: "conflict",
	});
	expect((await store.getTenant("acme"))?.signingKeys).toHaveLength(2);
});

test("A33: the opened keys are ES256 keys named by their RFC 7638 thumbprint, each signs what its public part verifies, and they come with the version of the tenant", async () => {
	const { auth, keys } = await createFixture();

	expect(valueFrom(await keys.load("acme"))).toEqual({ version: 1, keys: [] });

	await auth.tenants.rotateSigningKey("acme");

	const loaded = valueFrom(await keys.load("acme"));

	expect(loaded.version).toBe(2);
	expect(loaded.keys).toHaveLength(2);

	for (const key of loaded.keys) {
		expect(key.privateJwk).toMatchObject({
			kty: "EC",
			crv: "P-256",
			alg: "ES256",
			use: "sig",
			kid: key.kid,
		});
		expect(await thumbprintOf(key.privateJwk)).toBe(key.kid);
		expect(await signsAndVerifies(key.privateJwk)).toBe(true);
	}
});

test("A33: a revoked key is gone at once in any state; revoking the current key lets the next one sign at once and publishes a new next key", async () => {
	const { auth, keys } = await createFixture();
	const first = valueFrom(await auth.tenants.rotateSigningKey("acme"));

	later(HOUR);

	const second = valueFrom(await auth.tenants.rotateSigningKey("acme"));
	const withoutPrevious = valueFrom(
		await auth.tenants.revokeSigningKey("acme", kidIn(second, "previous")),
	);

	expect(withoutPrevious.map((key) => key.state).sort()).toEqual([
		"current",
		"next",
	]);
	expect(withoutPrevious.map((key) => key.kid)).not.toContain(
		kidIn(first, "current"),
	);

	const leaked = kidIn(withoutPrevious, "current");
	const promoted = kidIn(withoutPrevious, "next");
	const afterCurrent = valueFrom(
		await auth.tenants.revokeSigningKey("acme", leaked),
	);

	expect(kidIn(afterCurrent, "current")).toBe(promoted);
	expect(afterCurrent.map((key) => key.kid)).not.toContain(leaked);
	expect(afterCurrent).toHaveLength(2);

	const afterNext = valueFrom(
		await auth.tenants.revokeSigningKey("acme", kidIn(afterCurrent, "next")),
	);

	expect(kidIn(afterNext, "current")).toBe(promoted);
	expect(kidIn(afterNext, "next")).not.toBe(kidIn(afterCurrent, "next"));
	expect(await auth.tenants.revokeSigningKey("acme", leaked)).toEqual({
		ok: false,
		error: "no-key",
	});
	expect(
		valueFrom(await keys.load("acme")).keys.map((key) => key.kid),
	).not.toContain(leaked);
});

test("A33: a key row brought back or changed past the engine breaks the seal of its tenant: loading, rotating and signing in are refused", async () => {
	const { auth, keys, signIn, store } = await createFixture();

	await auth.tenants.rotateSigningKey("acme");
	later(HOUR);
	await auth.tenants.rotateSigningKey("acme");

	const before = await store.getSigningKeys("acme");

	if (before === undefined) {
		throw new Error("the tenant exists");
	}

	const previous = before.keys.find((key) => key.state === "previous");

	if (previous === undefined) {
		throw new Error("a previous key exists after two rotations");
	}

	await auth.tenants.revokeSigningKey("acme", previous.kid);

	const revoked = await store.getSigningKeys("acme");

	if (revoked === undefined) {
		throw new Error("the tenant exists");
	}

	const restore = (rows: readonly StoredSigningKey[]) =>
		store.setSigningKeys(revoked.tenant, revoked.tenant.seal, rows);

	expect(await restore([...revoked.keys, previous])).toBe(true);
	expect(await keys.load("acme")).toEqual({
		ok: false,
		error: "invalid-record",
	});
	expect(await auth.tenants.rotateSigningKey("acme")).toEqual({
		ok: false,
		error: "invalid-record",
	});
	expect(await signIn("acme")).toEqual({ ok: false, error: "invalid-record" });

	const promoted = revoked.keys.map((key) =>
		key.state === "next"
			? { ...key, state: "current" as const }
			: { ...key, state: "next" as const },
	);

	expect(await restore(promoted)).toBe(true);
	expect(await keys.load("acme")).toEqual({
		ok: false,
		error: "invalid-record",
	});

	expect(await restore(revoked.keys)).toBe(true);
	expect((await keys.load("acme")).ok).toBe(true);
	expect((await signIn("acme")).ok).toBe(true);
});

test("A33: a private key moved to another tenant does not open there, even under a seal that passes", async () => {
	const { auth, keys, records, store } = await createFixture();

	await auth.tenants.rotateSigningKey("acme");

	const acme = await store.getSigningKeys("acme");
	const globex = await store.getSigningKeys("globex");

	if (acme === undefined || globex === undefined) {
		throw new Error("both tenants exist");
	}

	const moved = await records.tenant({
		...globex.tenant,
		version: globex.tenant.version + 1,
		signingKeys: acme.tenant.signingKeys,
	});

	expect(await store.setSigningKeys(moved, globex.tenant.seal, acme.keys)).toBe(
		true,
	);
	expect(await keys.load("globex")).toEqual({
		ok: false,
		error: "invalid-record",
	});
});

test("A33: a rotation is recorded before its keys are written, and a revocation after its key is gone", async () => {
	const records: AuditRecord[] = [];
	let failing = false;
	const audit: AuditSink = async (record) => {
		if (failing && record.event === "signing-key.change") {
			throw new Error("the audit is down");
		}

		records.push(record);
	};
	const { auth, store } = await createFixture({ audit });

	failing = true;

	await expect(auth.tenants.rotateSigningKey("acme")).rejects.toThrow(
		"the audit is down",
	);
	expect((await store.getTenant("acme"))?.signingKeys).toEqual([]);

	failing = false;

	const rotated = valueFrom(await auth.tenants.rotateSigningKey("acme"));
	const next = kidIn(rotated, "next");

	expect(records.at(-1)).toMatchObject({
		event: "signing-key.change",
		outcome: "success",
		reason: "rotated",
		tenant: "acme",
		detail: { kid: kidIn(rotated, "current") },
	});

	failing = true;

	await expect(auth.tenants.revokeSigningKey("acme", next)).rejects.toThrow(
		"the audit is down",
	);
	expect(
		(await store.getTenant("acme"))?.signingKeys.map((key) => key.kid),
	).not.toContain(next);
});

test("A33: every change of a tenant through the engine raises its version, and sealing it again under a newer secret does not", async () => {
	const store = createMemoryAccountStore();
	const { auth, signIn } = await createFixture({ store });
	const versionOf = async () => (await store.getTenant("acme"))?.version;

	expect((await auth.tenants.create("acme")).ok).toBe(true);
	expect(await versionOf()).toBe(1);

	await auth.tenants.disable("acme");

	expect(await versionOf()).toBe(2);

	await auth.tenants.enable("acme");
	await auth.tenants.rotateSigningKey("acme");

	expect(await versionOf()).toBe(4);
	expect((await signIn("acme")).ok).toBe(true);

	const rotated = await createFixture({
		store,
		secrets: [NEW_SECRET, SECRET],
	});

	expect((await rotated.signIn("acme")).ok).toBe(true);
	expect((await store.getTenant("acme"))?.seal).toMatch(/^2\./);
	expect(await versionOf()).toBe(4);
});

test("A33: the propagation time is a positive number", () => {
	expect(() =>
		createAuth({
			accounts: createMemoryAccountStore(),
			grants: createMemoryGrantStore(),
			tokenStore: createMemoryTokenStore({ maximumBytes: 1_000 }),
			meterStore: createMemoryMeterStore({ maximumBytes: 1_000 }),
			secrets: [SECRET],
			factors: {},
			maximumLifeTimeMilliseconds: HOUR,
			sessionTimeToLiveMilliseconds: HOUR,
			signingKeyPropagationMilliseconds: 0,
			registration: () => "allow",
			policy: () => "allow",
			audit: async () => undefined,
		}),
	).toThrow(RangeError);
});
