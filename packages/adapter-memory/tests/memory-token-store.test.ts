import { createMemoryTokenStore } from "@vow-auth/adapter-memory";
import {
	createTokens,
	isStoreFullError,
	type TokenRecord,
	type TokenStore,
} from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/store-contracts";
import fastCheck from "fast-check";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

test("parallel takes of one record give it to exactly one caller", async () => {
	const store = createMemoryTokenStore({ maximumBytes: 100_000 });
	await store.put("hash", {
		purpose: "p",
		payload: {},
		expiresAtMilliseconds: 61_000,
	});

	const records = await Promise.all(
		Array.from({ length: 20 }, () => store.take("hash")),
	);

	expect(records.filter((record) => record !== undefined)).toHaveLength(1);
});

test("changing the payload after issue does not change the stored token", async () => {
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 100_000 }),
	});
	const payload = { email: "a@example.com" };
	const token = await tokens.issue({
		purpose: "email-link",
		payload,
		timeToLive: durationOf(60_000),
	});

	payload.email = "attacker@example.com";

	const result = await tokens.consume(token, "email-link");
	expect(result.ok && result.value.email).toBe("a@example.com");
});

test("the memory store keeps a deep copy of every record", async () => {
	const store = createMemoryTokenStore({ maximumBytes: 100_000 });
	const nested = { role: "user" };
	const record = {
		purpose: "p",
		payload: { nested } as unknown as Record<string, string>,
		expiresAtMilliseconds: 2_000,
	};

	await store.put("hash", record);
	nested.role = "admin";

	expect((await store.take("hash"))?.payload).toEqual({
		nested: { role: "user" },
	});
});

test("the memory store rejects invalid limits and records", async () => {
	for (const maximumBytes of [0, -1, 1.5, Number.NaN]) {
		expect(() => createMemoryTokenStore({ maximumBytes })).toThrow(RangeError);
	}

	const store = createMemoryTokenStore({ maximumBytes: 2_000 });

	await expect(
		store.put("hash", {
			purpose: "p",
			payload: {},
			expiresAtMilliseconds: Number.NaN,
		}),
	).rejects.toThrow(RangeError);
	await expect(
		store.put("hash", {
			purpose: "p",
			payload: { filler: "x".repeat(2_000) },
			expiresAtMilliseconds: 61_000,
		}),
	).rejects.toThrow(RangeError);
});

const costOf = (hash: string, record: TokenRecord): number => {
	return 256 + 2 * (hash.length + JSON.stringify(record).length);
};

const createRecord = (): TokenRecord => {
	return {
		purpose: "p",
		payload: { filler: "x".repeat(1_000) },
		expiresAtMilliseconds: 61_000,
	};
};

const takeAll = async (store: TokenStore, hashes: readonly string[]) => {
	const present: boolean[] = [];

	for (const hash of hashes) {
		present.push((await store.take(hash)) !== undefined);
	}

	return present;
};

test("a full memory store refuses new records and drops nothing that is alive", async () => {
	const hashes = Array.from(
		{ length: 100 },
		(_, index) => `hash-${String(index).padStart(3, "0")}`,
	);
	const store = createMemoryTokenStore({
		maximumBytes: 4 * costOf("hash-000", createRecord()) - 1,
	});
	const refused: boolean[] = [];

	for (const hash of hashes) {
		try {
			await store.put(hash, createRecord());
			refused.push(false);
		} catch (error) {
			expect(isStoreFullError(error)).toBe(true);
			refused.push(true);
		}
	}

	expect(refused).toEqual([...Array(3).fill(false), ...Array(97).fill(true)]);
	expect(await takeAll(store, hashes)).toEqual([
		...Array(3).fill(true),
		...Array(97).fill(false),
	]);
	expect(store.stats()).toMatchObject({ capacityRefusals: 97, evictions: 0 });
});

test("a refused replacement keeps the record that was there", async () => {
	const store = createMemoryTokenStore({
		maximumBytes: 2 * costOf("hash-000", createRecord()),
	});

	await store.put("hash-000", createRecord());
	await store.put("hash-001", createRecord());

	await expect(
		store.put("hash-000", {
			...createRecord(),
			payload: { filler: "x".repeat(2_000) },
		}),
	).rejects.toThrow();

	expect(await takeAll(store, ["hash-000", "hash-001"])).toEqual([true, true]);
});

test("taking or replacing a record frees its share of the memory budget", async () => {
	const store = createMemoryTokenStore({
		maximumBytes: 4 * costOf("hash-000", createRecord()) - 1,
	});

	for (const hash of ["hash-000", "hash-001", "hash-002"]) {
		await store.put(hash, createRecord());
	}

	await store.take("hash-001");
	await store.put("hash-003", createRecord());
	await store.put("hash-003", createRecord());

	expect(await takeAll(store, ["hash-000", "hash-002", "hash-003"])).toEqual([
		true,
		true,
		true,
	]);
});

const checkAgainstModel = async (maximumBytes: number) => {
	const hashes = Array.from(
		{ length: 32 },
		(_, index) => `hash-${String(index).padStart(2, "0")}`,
	);
	const hash = fastCheck.constantFrom(...hashes);
	const operation = fastCheck.oneof(
		fastCheck.record({
			kind: fastCheck.constant("put" as const),
			hash,
			lifetime: fastCheck.integer({ min: 1, max: 100 }),
			payloadSize: fastCheck.integer({ min: 0, max: 300 }),
		}),
		fastCheck.record({ kind: fastCheck.constant("take" as const), hash }),
		fastCheck.record({
			kind: fastCheck.constant("wait" as const),
			duration: fastCheck.integer({ min: 0, max: 10 }),
		}),
	);

	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.array(operation, { maxLength: 200, size: "max" }),
			async (operations) => {
				vi.setSystemTime(1_000);
				const store = createMemoryTokenStore({ maximumBytes });
				const model = new Map<string, TokenRecord>();

				const liveBytesWithout = (excluded: string): number => {
					let bytes = 0;

					for (const [modelHash, record] of model) {
						if (
							modelHash !== excluded &&
							Date.now() < record.expiresAtMilliseconds
						) {
							bytes += costOf(modelHash, record);
						}
					}

					return bytes;
				};

				const takeAndCheck = async (takenHash: string) => {
					const expected = model.get(takenHash);
					const live =
						expected !== undefined &&
						Date.now() < expected.expiresAtMilliseconds;
					const actual = await store.take(takenHash);

					expect(actual).toEqual(live ? expected : undefined);
					model.delete(takenHash);

					return actual;
				};

				for (const step of operations) {
					if (step.kind === "wait") {
						vi.advanceTimersByTime(step.duration);
						continue;
					}

					if (step.kind === "take") {
						await takeAndCheck(step.hash);
						continue;
					}

					const record: TokenRecord = {
						purpose: "p",
						payload: { filler: "x".repeat(step.payloadSize) },
						expiresAtMilliseconds: Date.now() + step.lifetime,
					};
					const fits =
						liveBytesWithout(step.hash) + costOf(step.hash, record) <=
						maximumBytes;

					if (fits) {
						await store.put(step.hash, record);
						model.delete(step.hash);
						model.set(step.hash, record);
					} else {
						await expect(store.put(step.hash, record)).rejects.toSatisfy(
							isStoreFullError,
						);
					}
				}

				let presentBytes = 0;

				for (const presentHash of hashes) {
					const record = await takeAndCheck(presentHash);

					if (record !== undefined) {
						presentBytes += costOf(presentHash, record);
					}
				}

				expect(presentBytes).toBeLessThanOrEqual(maximumBytes);
			},
		),
		{ numRuns: 500 },
	);
};

test("a roomy memory store keeps exactly its live records under any operation order", async () => {
	await checkAgainstModel(10_000_000);
});

test("a cramped memory store refuses exactly when its live records leave no room, and drops none", async () => {
	await checkAgainstModel(4_000);
});
