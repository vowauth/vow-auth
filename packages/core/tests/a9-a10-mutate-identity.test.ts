import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
} from "@vow-auth/adapter-memory";
import {
	type AuditRecord,
	type AuditSink,
	createMutateIdentity,
	createSealer,
	createSessionTokens,
	evaluatePolicy,
	type Factor,
	type IdentityStore,
	issueSession,
	type Proof,
	resolveIdentity,
	succeed,
	verifyProof,
} from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/test-support";
import { expect, test, vi } from "vitest";

const LIFE_TIME = 60_000;

const proofOf = async (claims: unknown): Promise<Proof> => {
	const factor: Factor = {
		id: "test-factor",
		strength: "possession",
		verify: async () => succeed(claims),
	};
	const result = await verifyProof(factor, undefined);

	if (!result.ok) {
		throw new Error("the proof must be minted");
	}

	return result.value;
};

const verifiedEmail = (email: string) =>
	proofOf({
		provider: "email",
		externalId: email,
		email,
		emailVerified: true,
	});

const unverifiedClaim = (provider: string, externalId: string, email: string) =>
	proofOf({ provider, externalId, email, emailVerified: false });

const createFixture = (audit?: AuditSink) => {
	const store = createMemoryIdentityStore();
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: "mutate-secret-0123456789abcdefghijkl" }],
		}),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		maximumLifeTimeMilliseconds: LIFE_TIME,
	});
	const mutateIdentity = createMutateIdentity({
		store,
		sessionTokens,
		...(audit === undefined ? {} : { audit }),
	});

	const signIn = async (
		tenant: string,
		proof: Proof,
		device = "laptop",
	): Promise<{ subjectId: string; token: string }> => {
		const resolution = await resolveIdentity(store, tenant, proof);

		if (!resolution.ok) {
			throw new Error("the identity must resolve");
		}

		const session = issueSession(
			await evaluatePolicy(resolution.value.subjectId, () => "allow"),
		);

		if (!session.ok) {
			throw new Error("an allowed session must be born");
		}

		const token = await sessionTokens.issue(session.value, {
			tenant,
			device,
			timeToLive: durationOf(LIFE_TIME),
			methods: ["test"],
		});

		if (!token.ok) {
			throw new Error("a born session must get a token");
		}

		return { subjectId: resolution.value.subjectId, token: token.value };
	};

	const isValid = async (token: string) =>
		(await sessionTokens.verify(token)).ok;

	return { isValid, mutateIdentity, sessionTokens, signIn, store };
};

test("A9: confirming an email evicts the account and sessions that claimed it earlier", async () => {
	const { isValid, mutateIdentity, signIn, store } = createFixture();
	const squatter = await signIn(
		"acme",
		await unverifiedClaim("evil", "e-1", "victim@example.com"),
	);
	const victim = await signIn(
		"acme",
		await verifiedEmail("victim@example.com"),
	);

	expect(victim.subjectId).not.toBe(squatter.subjectId);
	expect(await isValid(squatter.token)).toBe(true);

	const result = await mutateIdentity("acme", victim.subjectId, {
		type: "confirm-email",
		proof: await verifiedEmail("victim@example.com"),
	});

	expect(result.ok && result.value.affectedSubjects).toEqual([
		squatter.subjectId,
	]);
	expect(await isValid(squatter.token)).toBe(false);
	expect(await isValid(victim.token)).toBe(true);
	expect(await store.findSubject("acme", "evil", "e-1")).toBeUndefined();
});

test("A9: a subject with another identity stays, loses only the claim, and loses its sessions", async () => {
	const { isValid, mutateIdentity, signIn, store } = createFixture();
	const mixed = await signIn(
		"acme",
		await proofOf({
			provider: "google",
			externalId: "g-1",
			email: "other@example.com",
			emailVerified: true,
		}),
	);
	const claim = await unverifiedClaim("github", "gh-1", "victim@example.com");

	await store.linkIdentity("acme", mixed.subjectId, claim.claims);

	const victim = await signIn(
		"acme",
		await verifiedEmail("victim@example.com"),
	);
	const result = await mutateIdentity("acme", victim.subjectId, {
		type: "confirm-email",
		proof: await verifiedEmail("victim@example.com"),
	});

	expect(result.ok && result.value.affectedSubjects).toEqual([mixed.subjectId]);
	expect(await store.findSubject("acme", "google", "g-1")).toBe(
		mixed.subjectId,
	);
	expect(await store.findSubject("acme", "github", "gh-1")).toBeUndefined();
	expect(await isValid(mixed.token)).toBe(false);
});

test("A9: another tenant's claims are untouched", async () => {
	const { isValid, mutateIdentity, signIn } = createFixture();
	const elsewhere = await signIn(
		"globex",
		await unverifiedClaim("evil", "e-1", "victim@example.com"),
	);
	const victim = await signIn(
		"acme",
		await verifiedEmail("victim@example.com"),
	);

	await mutateIdentity("acme", victim.subjectId, {
		type: "confirm-email",
		proof: await verifiedEmail("victim@example.com"),
	});

	expect(await isValid(elsewhere.token)).toBe(true);
});

test("A9: only the verified owner of the email can confirm it", async () => {
	const { mutateIdentity, signIn } = createFixture();
	const victim = await signIn(
		"acme",
		await verifiedEmail("victim@example.com"),
	);
	const other = await signIn("acme", await verifiedEmail("other@example.com"));
	const unverified = await unverifiedClaim("p", "x", "victim@example.com");
	const verifiedProof = await verifiedEmail("victim@example.com");

	const cases = [
		await mutateIdentity("acme", other.subjectId, {
			type: "confirm-email",
			proof: verifiedProof,
		}),
		await mutateIdentity("globex", victim.subjectId, {
			type: "confirm-email",
			proof: verifiedProof,
		}),
		await mutateIdentity("acme", victim.subjectId, {
			type: "confirm-email",
			proof: unverified,
		}),
		await mutateIdentity("acme", victim.subjectId, {
			type: "confirm-email",
			proof: { forged: true },
		}),
	];

	expect(cases.map((result) => !result.ok && result.error)).toEqual([
		"forbidden",
		"forbidden",
		"forbidden",
		"no-proof",
	]);
});

test("A10: deleting a subject revokes every session and removes every binding", async () => {
	const { isValid, mutateIdentity, signIn, store } = createFixture();
	const laptop = await signIn(
		"acme",
		await verifiedEmail("alice@example.com"),
		"laptop",
	);
	const phone = await signIn(
		"acme",
		await verifiedEmail("alice@example.com"),
		"phone",
	);
	const bob = await signIn("acme", await verifiedEmail("bob@example.com"));

	expect(phone.subjectId).toBe(laptop.subjectId);

	const result = await mutateIdentity("acme", laptop.subjectId, {
		type: "delete",
	});

	expect(result.ok && result.value.affectedSubjects).toEqual([
		laptop.subjectId,
	]);
	expect(await isValid(laptop.token)).toBe(false);
	expect(await isValid(phone.token)).toBe(false);
	expect(await isValid(bob.token)).toBe(true);
	expect(
		await store.findSubject("acme", "email", "alice@example.com"),
	).toBeUndefined();

	const again = await signIn("acme", await verifiedEmail("alice@example.com"));

	expect(again.subjectId).not.toBe(laptop.subjectId);
});

test("A10: a delete never reaches a subject of another tenant", async () => {
	const { isValid, mutateIdentity, signIn, store } = createFixture();
	const alice = await signIn("acme", await verifiedEmail("alice@example.com"));

	const result = await mutateIdentity("globex", alice.subjectId, {
		type: "delete",
	});

	expect(!result.ok && result.error).toBe("no-subject");
	expect(await isValid(alice.token)).toBe(true);
	expect(await store.findSubject("acme", "email", "alice@example.com")).toBe(
		alice.subjectId,
	);
});

test("sessions are revoked before the store changes, so a failure never leaves a live session", async () => {
	const { isValid, sessionTokens, signIn, store } = createFixture();
	const alice = await signIn("acme", await verifiedEmail("alice@example.com"));
	const failing: IdentityStore = {
		...store,
		deleteSubject: async () => {
			throw new Error("the database is down");
		},
	};
	const mutateIdentity = createMutateIdentity({
		store: failing,
		sessionTokens,
	});

	await expect(
		mutateIdentity("acme", alice.subjectId, { type: "delete" }),
	).rejects.toThrow("the database is down");
	expect(await isValid(alice.token)).toBe(false);
	expect(await store.findSubject("acme", "email", "alice@example.com")).toBe(
		alice.subjectId,
	);
});

test("a failing revocation changes nothing in the store", async () => {
	const { signIn, store } = createFixture();
	const alice = await signIn("acme", await verifiedEmail("alice@example.com"));
	const deleteSpy = vi.spyOn(store, "deleteSubject");
	const mutateIdentity = createMutateIdentity({
		store,
		sessionTokens: {
			revoke: async () => {
				throw new Error("the epoch store is down");
			},
		},
	});

	await expect(
		mutateIdentity("acme", alice.subjectId, { type: "delete" }),
	).rejects.toThrow("the epoch store is down");
	expect(deleteSpy).not.toHaveBeenCalled();
});

test("changes are recorded, and a failing sink still leaves the change done", async () => {
	const records: AuditRecord[] = [];
	const collecting: AuditSink = async (record) => {
		records.push(record);
	};
	const { mutateIdentity, signIn } = createFixture(collecting);
	const squatter = await signIn(
		"acme",
		await unverifiedClaim("evil", "e-1", "victim@example.com"),
	);
	const victim = await signIn(
		"acme",
		await verifiedEmail("victim@example.com"),
	);

	await mutateIdentity("acme", victim.subjectId, {
		type: "confirm-email",
		proof: await verifiedEmail("victim@example.com"),
	});
	await mutateIdentity("globex", victim.subjectId, { type: "delete" });
	await mutateIdentity("acme", squatter.subjectId, { type: "delete" });

	expect(
		records.map((record) => [record.event, record.outcome, record.reason]),
	).toEqual([
		["identity.mutate", "success", "email-confirmed"],
		["identity.mutate", "refusal", "not-found"],
		["identity.mutate", "refusal", "not-found"],
	]);
	expect(records[0]?.detail).toEqual({ change: "confirm-email", evicted: "1" });

	const failing = createFixture(async () => {
		throw new Error("the audit store is down");
	});
	const alice = await failing.signIn(
		"acme",
		await verifiedEmail("alice@example.com"),
	);

	await expect(
		failing.mutateIdentity("acme", alice.subjectId, { type: "delete" }),
	).rejects.toThrow("the audit store is down");
	expect(await failing.isValid(alice.token)).toBe(false);
});
