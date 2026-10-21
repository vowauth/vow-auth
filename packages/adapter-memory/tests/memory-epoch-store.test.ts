import { createMemoryEpochStore } from "@vow-auth/adapter-memory";
import {
	createSealer,
	createSessionTokens,
	type EpochStore,
	evaluatePolicy,
	type RevocationLevel,
	type SessionTokens,
} from "@vow-auth/core";
import { issueSession } from "@vow-auth/core/testing";
import fastCheck from "fast-check";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const MAXIMUM_LIFE_TIME = 1_000;
const sealer = createSealer({
	secrets: [{ version: 1, value: "session-secret-0123456789abcdefghijk" }],
});

const createTokensOver = (epochs: EpochStore) => {
	return createSessionTokens({
		sealer,
		epochs,
		maximumLifeTimeMilliseconds: MAXIMUM_LIFE_TIME,
	});
};

const issueFor = async (
	sessionTokens: SessionTokens,
	subject: string,
	device = "laptop",
	timeToLiveMilliseconds = MAXIMUM_LIFE_TIME,
) => {
	const session = issueSession(await evaluatePolicy(subject, () => "allow"));

	if (!session.ok) {
		throw new Error("an allowed session must be born");
	}

	const token = await sessionTokens.issue(session.value, {
		tenant: "acme",
		device,
		timeToLiveMilliseconds,
	});

	if (!token.ok) {
		throw new Error("a born session must get a token");
	}

	return { token: token.value, session: session.value.id };
};

const isValid = async (sessionTokens: SessionTokens, token: string) => {
	return (await sessionTokens.verify(token)).ok;
};

test("a restart revokes every token issued before it", async () => {
	const before = createTokensOver(
		createMemoryEpochStore({ maximumBytes: 100_000 }),
	);
	const { token } = await issueFor(before, "alice");

	vi.advanceTimersByTime(MAXIMUM_LIFE_TIME / 2);
	const after = createTokensOver(
		createMemoryEpochStore({ maximumBytes: 100_000 }),
	);
	const fresh = await issueFor(after, "alice");

	expect(await isValid(after, token)).toBe(false);
	expect(await isValid(after, fresh.token)).toBe(true);
});

test("expired revocations free their share of the budget", async () => {
	const epochs = createMemoryEpochStore({ maximumBytes: 300 });

	for (let index = 0; index < 50; index += 1) {
		await epochs.revoke(`{acme}:user:user-${index}`, MAXIMUM_LIFE_TIME);
		vi.advanceTimersByTime(MAXIMUM_LIFE_TIME);
	}

	expect((await epochs.read(["{acme}:user:never-revoked"])).stamps).toEqual([
		1_000,
	]);
});

test("an overflow revokes every token instead of reviving a revoked one", async () => {
	const sessionTokens = createTokensOver(
		createMemoryEpochStore({ maximumBytes: 700 }),
	);
	const alice = await issueFor(sessionTokens, "alice");
	const bob = await issueFor(sessionTokens, "bob");
	const carol = await issueFor(sessionTokens, "carol");

	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "alice" });
	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "bob" });
	expect(await isValid(sessionTokens, carol.token)).toBe(true);

	await sessionTokens.revoke({ tenant: "acme", scope: "device", id: "phone" });

	for (const { token } of [alice, bob, carol]) {
		expect(await isValid(sessionTokens, token)).toBe(false);
	}

	expect(
		await isValid(
			sessionTokens,
			(await issueFor(sessionTokens, "alice")).token,
		),
	).toBe(true);
});

test("a budget smaller than one revocation still revokes, by revoking everything", async () => {
	const sessionTokens = createTokensOver(
		createMemoryEpochStore({ maximumBytes: 100 }),
	);
	const alice = await issueFor(sessionTokens, "alice");

	vi.advanceTimersByTime(1);
	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "alice" });

	expect(await isValid(sessionTokens, alice.token)).toBe(false);
});

test("revocations within one millisecond stay revoked through an overflow", async () => {
	const sessionTokens = createTokensOver(
		createMemoryEpochStore({ maximumBytes: 1_500 }),
	);
	const session = issueSession(await evaluatePolicy("alice", () => "allow"));

	if (!session.ok) {
		throw new Error("an allowed session must be born");
	}

	vi.advanceTimersByTime(1);
	await sessionTokens.revoke({ tenant: "acme", scope: "tenant" });
	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "alice" });
	await sessionTokens.revoke({ tenant: "acme", scope: "device", id: "laptop" });
	await sessionTokens.revoke({
		tenant: "acme",
		scope: "session",
		id: session.value.id,
	});
	const issued = await sessionTokens.issue(session.value, {
		tenant: "acme",
		device: "laptop",
		timeToLiveMilliseconds: MAXIMUM_LIFE_TIME,
	});
	const token = issued.ok ? issued.value : "";
	expect(await isValid(sessionTokens, token)).toBe(true);

	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "alice" });
	expect(await isValid(sessionTokens, token)).toBe(false);

	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "bob" });
	expect(await isValid(sessionTokens, token)).toBe(false);
});

test("an invalid budget is a configuration error", () => {
	for (const maximumBytes of [0, -1, 1.5, Number.NaN]) {
		expect(() => createMemoryEpochStore({ maximumBytes })).toThrow(RangeError);
	}
});

const checkAgainstModel = async (maximumBytes: number, exact: boolean) => {
	const scopes = ["tenant", "user", "device", "session"] as const;
	const operation = fastCheck.oneof(
		fastCheck.record({
			kind: fastCheck.constant("issue" as const),
			user: fastCheck.constantFrom("alice", "bob"),
			device: fastCheck.constantFrom("laptop", "phone"),
			lifetime: fastCheck.integer({ min: 1, max: MAXIMUM_LIFE_TIME }),
		}),
		fastCheck.record({
			kind: fastCheck.constant("revoke" as const),
			token: fastCheck.nat(),
			scope: fastCheck.constantFrom(...scopes),
		}),
		fastCheck.record({
			kind: fastCheck.constant("wait" as const),
			duration: fastCheck.integer({ min: 0, max: 700 }),
		}),
		fastCheck.record({
			kind: fastCheck.constant("verify" as const),
			token: fastCheck.nat(),
		}),
	);

	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.array(operation, { maxLength: 60, size: "max" }),
			async (operations) => {
				vi.setSystemTime(1_000);
				const sessionTokens = createTokensOver(
					createMemoryEpochStore({ maximumBytes }),
				);
				const issued: {
					readonly token: string;
					readonly levels: readonly RevocationLevel[];
					readonly sequence: number;
					readonly expiresAtMilliseconds: number;
				}[] = [];
				const lastRevocation = new Map<string, number>();
				const levelKey = (level: RevocationLevel) =>
					JSON.stringify([
						level.scope,
						level.scope === "tenant" ? "" : level.id,
					]);

				for (const [sequence, step] of operations.entries()) {
					if (step.kind === "wait") {
						vi.advanceTimersByTime(step.duration);
						continue;
					}

					if (step.kind === "issue") {
						const { token, session } = await issueFor(
							sessionTokens,
							step.user,
							step.device,
							step.lifetime,
						);
						issued.push({
							token,
							levels: [
								{ tenant: "acme", scope: "tenant" },
								{ tenant: "acme", scope: "user", id: step.user },
								{ tenant: "acme", scope: "device", id: step.device },
								{ tenant: "acme", scope: "session", id: session },
							],
							sequence,
							expiresAtMilliseconds: Date.now() + step.lifetime,
						});
						continue;
					}

					const target = issued[step.token % Math.max(issued.length, 1)];

					if (target === undefined) {
						continue;
					}

					if (step.kind === "revoke") {
						const level = target.levels[scopes.indexOf(step.scope)];

						if (level !== undefined) {
							await sessionTokens.revoke(level);
							lastRevocation.set(levelKey(level), sequence);
						}

						continue;
					}

					const allowedByModel =
						Date.now() < target.expiresAtMilliseconds &&
						target.levels.every(
							(level) =>
								(lastRevocation.get(levelKey(level)) ?? -1) < target.sequence,
						);
					const valid = await isValid(sessionTokens, target.token);

					if (exact) {
						expect(valid).toBe(allowedByModel);
					} else if (valid) {
						expect(allowedByModel).toBe(true);
					}
				}
			},
		),
		{ numRuns: 200 },
	);
};

test("over a roomy memory epoch store, session tokens follow the revocation model exactly", async () => {
	await checkAgainstModel(10_000_000, true);
});

test("over a cramped memory epoch store, no revoked token ever passes", async () => {
	await checkAgainstModel(700, false);
});
