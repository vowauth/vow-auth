import {
	createSealer,
	createSessionTokens,
	type EpochStore,
	evaluatePolicy,
	issueSession,
	type RevocationLevel,
	type Session,
	type SessionTokens,
} from "@vow-auth/core";
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

const createMapEpochStore = (clock: () => number = () => Date.now()) => {
	const entries = new Map<
		string,
		{ readonly stamp: number; readonly expiresAtMilliseconds: number }
	>();
	let readCalls = 0;

	const currentStamp = (key: string): number => {
		const entry = entries.get(key);

		return entry !== undefined && clock() < entry.expiresAtMilliseconds
			? entry.stamp
			: 0;
	};

	const store: EpochStore = {
		async read(keys) {
			readCalls += 1;

			return { now: clock(), stamps: keys.map(currentStamp) };
		},
		async revoke(key, timeToLiveMilliseconds) {
			const stamp = Math.max(currentStamp(key) + 1, clock());
			entries.set(key, {
				stamp,
				expiresAtMilliseconds: clock() + timeToLiveMilliseconds,
			});

			return stamp;
		},
	};

	return { store, readCalls: () => readCalls };
};

const createFixture = (clock?: () => number) => {
	const epochs = createMapEpochStore(clock);
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: "session-secret-0123456789abcdefghijk" }],
		}),
		epochs: epochs.store,
		maximumLifeTimeMilliseconds: MAXIMUM_LIFE_TIME,
	});

	return { epochs, sessionTokens };
};

const bornSession = async (subject: string): Promise<Session> => {
	const result = issueSession(await evaluatePolicy(subject, () => "allow"));

	if (!result.ok) {
		throw new Error("an allowed session must be born");
	}

	return result.value;
};

const issueToken = async (
	sessionTokens: SessionTokens,
	session: Session,
	tenant: string,
	device: string,
	timeToLiveMilliseconds = MAXIMUM_LIFE_TIME,
): Promise<string> => {
	const result = await sessionTokens.issue(session, {
		tenant,
		device,
		timeToLiveMilliseconds,
	});

	if (!result.ok) {
		throw new Error("a born session must get a token");
	}

	return result.value;
};

const isValid = async (sessionTokens: SessionTokens, token: string) => {
	return (await sessionTokens.verify(token)).ok;
};

test("a token verifies to its identity with one read of the epoch store", async () => {
	const { epochs, sessionTokens } = createFixture();
	const session = await bornSession("alice");
	const token = await issueToken(sessionTokens, session, "acme", "laptop");
	const readsBefore = epochs.readCalls();

	const verified = await sessionTokens.verify(token);

	expect(verified.ok && verified.value).toEqual({
		tenant: "acme",
		subject: "alice",
		device: "laptop",
		session: session.id,
	});
	expect(epochs.readCalls() - readsBefore).toBe(1);
});

test("revoking a level kills exactly the tokens below it", async () => {
	const { sessionTokens } = createFixture();
	const alice = await bornSession("alice");
	const aliceAgain = await bornSession("alice");
	const bob = await bornSession("bob");
	const tokens = {
		aliceLaptop: await issueToken(sessionTokens, alice, "acme", "laptop"),
		alicePhone: await issueToken(sessionTokens, aliceAgain, "acme", "phone"),
		bobLaptop: await issueToken(sessionTokens, bob, "acme", "laptop"),
		aliceElsewhere: await issueToken(sessionTokens, alice, "globex", "laptop"),
	};
	const survivors = async () => {
		const result: string[] = [];

		for (const [name, token] of Object.entries(tokens)) {
			if (await isValid(sessionTokens, token)) {
				result.push(name);
			}
		}

		return result;
	};

	await sessionTokens.revoke({
		tenant: "acme",
		scope: "session",
		id: alice.id,
	});
	expect(await survivors()).toEqual([
		"alicePhone",
		"bobLaptop",
		"aliceElsewhere",
	]);

	await sessionTokens.revoke({ tenant: "acme", scope: "device", id: "laptop" });
	expect(await survivors()).toEqual(["alicePhone", "aliceElsewhere"]);

	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "alice" });
	expect(await survivors()).toEqual(["aliceElsewhere"]);

	await sessionTokens.revoke({ tenant: "globex", scope: "tenant" });
	expect(await survivors()).toEqual([]);
});

test("a token issued while a revocation key lived dies at the next revocation, even after the key expired", async () => {
	const { sessionTokens } = createFixture();
	const user: RevocationLevel = { tenant: "acme", scope: "user", id: "alice" };

	await sessionTokens.revoke(user);
	vi.advanceTimersByTime(0.5 * MAXIMUM_LIFE_TIME);
	const token = await issueToken(
		sessionTokens,
		await bornSession("alice"),
		"acme",
		"laptop",
	);

	vi.advanceTimersByTime(0.6 * MAXIMUM_LIFE_TIME);
	expect(await isValid(sessionTokens, token)).toBe(true);

	await sessionTokens.revoke(user);
	expect(await isValid(sessionTokens, token)).toBe(false);

	const later = await issueToken(
		sessionTokens,
		await bornSession("alice"),
		"acme",
		"laptop",
	);
	expect(await isValid(sessionTokens, later)).toBe(true);
});

test("expiry and revocation follow the epoch store clock, whatever the local clock says", async () => {
	let offset = 0;
	const { sessionTokens } = createFixture(() => Date.now() + offset);
	const shiftLocalClock = (delta: number) => {
		vi.setSystemTime(Date.now() + delta);
		offset -= delta;
	};
	const token = await issueToken(
		sessionTokens,
		await bornSession("alice"),
		"acme",
		"laptop",
	);

	shiftLocalClock(-5 * MAXIMUM_LIFE_TIME);
	vi.advanceTimersByTime(MAXIMUM_LIFE_TIME);
	expect(await isValid(sessionTokens, token)).toBe(false);

	const revoked = await issueToken(
		sessionTokens,
		await bornSession("alice"),
		"acme",
		"laptop",
	);
	await sessionTokens.revoke({ tenant: "acme", scope: "user", id: "alice" });
	vi.advanceTimersByTime(MAXIMUM_LIFE_TIME - 1);
	shiftLocalClock(-5 * MAXIMUM_LIFE_TIME);
	expect(await isValid(sessionTokens, revoked)).toBe(false);
});

test("a sealed session of an unknown chain shape is rejected", async () => {
	const { sessionTokens } = createFixture();
	const sealer = createSealer({
		secrets: [{ version: 1, value: "session-secret-0123456789abcdefghijk" }],
	});
	const known = [
		["tenant", "acme", 0],
		["user", "alice", 0],
		["device", "laptop", 0],
		["session", "s-1", 0],
	];

	const sealChain = (chain: readonly unknown[]) => {
		return sealer.seal({
			purpose: "session",
			payload: {
				chain: JSON.stringify(chain),
				expiresAtMilliseconds: String(Date.now() + MAXIMUM_LIFE_TIME),
			},
			timeToLiveMilliseconds: MAXIMUM_LIFE_TIME,
		});
	};

	expect((await sessionTokens.verify(await sealChain(known))).ok).toBe(true);

	for (const chain of [
		[...known, ["agent", "a-5", 0]],
		known.slice(0, 3),
		[known[1], known[0], known[2], known[3]],
		known.map(([scope, id]) => [scope, id, "0"]),
		known.map(([scope, , stamp]) => [scope, 7, stamp]),
	]) {
		expect((await sessionTokens.verify(await sealChain(chain))).ok).toBe(false);
	}
});

test("only a session born from an allow decision gets a token", async () => {
	const { sessionTokens } = createFixture();
	const session = await bornSession("alice");

	expect(Reflect.set(session, "subject", "admin")).toBe(false);

	for (const forged of [
		{ id: session.id, subject: "admin" },
		JSON.parse(JSON.stringify(session)),
	]) {
		expect(
			await sessionTokens.issue(forged, {
				tenant: "acme",
				device: "laptop",
				timeToLiveMilliseconds: MAXIMUM_LIFE_TIME,
			}),
		).toEqual({ ok: false, error: "no-session" });
	}
});

test("anything but a session token is rejected with one error", async () => {
	const { sessionTokens } = createFixture();
	const otherPurpose = await createSealer({
		secrets: [{ version: 1, value: "session-secret-0123456789abcdefghijk" }],
	}).seal({
		purpose: "oauth-state",
		payload: { chain: "[]" },
		timeToLiveMilliseconds: MAXIMUM_LIFE_TIME,
	});

	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.string(), async (guess) => {
			expect(await sessionTokens.verify(guess)).toEqual({
				ok: false,
				error: "invalid-session",
			});
		}),
	);
	expect(await sessionTokens.verify(otherPurpose)).toEqual({
		ok: false,
		error: "invalid-session",
	});
});

test("lifetimes beyond the configured maximum are a programming error", async () => {
	const { sessionTokens } = createFixture();
	const session = await bornSession("alice");

	for (const maximumLifeTimeMilliseconds of [0, -1, Number.NaN, Infinity]) {
		expect(() =>
			createSessionTokens({
				sealer: createSealer({
					secrets: [
						{ version: 1, value: "session-secret-0123456789abcdefghijk" },
					],
				}),
				epochs: createMapEpochStore().store,
				maximumLifeTimeMilliseconds,
			}),
		).toThrow(RangeError);
	}

	for (const timeToLiveMilliseconds of [
		0,
		-1,
		Number.NaN,
		MAXIMUM_LIFE_TIME + 1,
	]) {
		await expect(
			sessionTokens.issue(session, {
				tenant: "acme",
				device: "laptop",
				timeToLiveMilliseconds,
			}),
		).rejects.toThrow(RangeError);
	}
});

test("an epoch store that breaks its contract fails loudly, never open", async () => {
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: "session-secret-0123456789abcdefghijk" }],
		}),
		epochs: {
			read: async () => ({ now: Date.now(), stamps: [0] }),
			revoke: async () => 0,
		},
		maximumLifeTimeMilliseconds: MAXIMUM_LIFE_TIME,
	});

	await expect(
		sessionTokens.issue(await bornSession("alice"), {
			tenant: "acme",
			device: "laptop",
			timeToLiveMilliseconds: MAXIMUM_LIFE_TIME,
		}),
	).rejects.toThrow("EpochStore.read");
});

test("no token issued before a revocation passes after it, under any order of events", async () => {
	const tenants = ["acme", "globex"];
	const users = ["alice", "bob"];
	const devices = ["laptop", "phone"];
	const scopes = ["tenant", "user", "device", "session"] as const;
	const operation = fastCheck.oneof(
		fastCheck.record({
			kind: fastCheck.constant("issue" as const),
			tenant: fastCheck.constantFrom(...tenants),
			user: fastCheck.constantFrom(...users),
			device: fastCheck.constantFrom(...devices),
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
		fastCheck.record({
			kind: fastCheck.constant("skew" as const),
			duration: fastCheck.integer({ min: -3_000, max: 3_000 }),
		}),
	);

	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.array(operation, { maxLength: 60, size: "max" }),
			async (operations) => {
				vi.setSystemTime(1_000);
				let offset = 0;
				const storeNow = () => Date.now() + offset;
				const { sessionTokens } = createFixture(storeNow);
				const issued: {
					readonly token: string;
					readonly levels: readonly RevocationLevel[];
					readonly sequence: number;
					readonly expiresAtStoreMilliseconds: number;
					readonly expiresAtLocalMilliseconds: number;
				}[] = [];
				const lastRevocation = new Map<string, number>();
				const levelKey = (level: RevocationLevel) =>
					JSON.stringify([
						level.tenant,
						level.scope,
						level.scope === "tenant" ? "" : level.id,
					]);

				for (const [sequence, step] of operations.entries()) {
					if (step.kind === "wait") {
						vi.advanceTimersByTime(step.duration);
						continue;
					}

					if (step.kind === "skew") {
						vi.setSystemTime(Date.now() + step.duration);
						offset -= step.duration;
						continue;
					}

					if (step.kind === "issue") {
						const session = await bornSession(step.user);
						issued.push({
							token: await issueToken(
								sessionTokens,
								session,
								step.tenant,
								step.device,
								step.lifetime,
							),
							levels: [
								{ tenant: step.tenant, scope: "tenant" },
								{ tenant: step.tenant, scope: "user", id: step.user },
								{ tenant: step.tenant, scope: "device", id: step.device },
								{ tenant: step.tenant, scope: "session", id: session.id },
							],
							sequence,
							expiresAtStoreMilliseconds: storeNow() + step.lifetime,
							expiresAtLocalMilliseconds: Date.now() + step.lifetime,
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

					const expected =
						storeNow() < target.expiresAtStoreMilliseconds &&
						Date.now() < target.expiresAtLocalMilliseconds &&
						target.levels.every(
							(level) =>
								(lastRevocation.get(levelKey(level)) ?? -1) < target.sequence,
						);

					expect(await isValid(sessionTokens, target.token)).toBe(expected);
				}
			},
		),
		{ numRuns: 300 },
	);
});
