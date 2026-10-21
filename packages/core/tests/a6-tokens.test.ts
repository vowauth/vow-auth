import {
	createTokens,
	type TokenRecord,
	type TokenStore,
} from "@vow-auth/core/internal";
import fastCheck from "fast-check";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const createMapTokenStore = (): TokenStore => {
	const records = new Map<string, TokenRecord>();

	return {
		async put(hash, record) {
			records.set(hash, record);
		},
		async take(hash) {
			const record = records.get(hash);
			records.delete(hash);

			return record;
		},
	};
};

const createFixture = () => {
	const tokens = createTokens({ store: createMapTokenStore() });

	return { tokens };
};

test("a token is redeemed once with its payload", async () => {
	const { tokens } = createFixture();
	const token = await tokens.issue({
		purpose: "email-link",
		payload: { email: "a@example.com" },
		timeToLiveMilliseconds: 60_000,
	});

	const first = await tokens.consume(token, "email-link");
	const second = await tokens.consume(token, "email-link");

	expect(first.ok && first.value).toEqual({ email: "a@example.com" });
	expect(second.ok).toBe(false);
});

test("a token of one purpose is rejected for another and burned", async () => {
	const { tokens } = createFixture();
	const token = await tokens.issue({
		purpose: "oauth-state",
		timeToLiveMilliseconds: 60_000,
	});

	const wrong = await tokens.consume(token, "email-link");
	const right = await tokens.consume(token, "oauth-state");

	expect(wrong.ok).toBe(false);
	expect(right.ok).toBe(false);
});

test("parallel redemption succeeds exactly once", async () => {
	const { tokens } = createFixture();
	const token = await tokens.issue({
		purpose: "email-link",
		timeToLiveMilliseconds: 60_000,
	});

	const results = await Promise.all(
		Array.from({ length: 20 }, () => tokens.consume(token, "email-link")),
	);

	expect(results.filter((result) => result.ok)).toHaveLength(1);
});

test("an expired token is rejected", async () => {
	const { tokens } = createFixture();
	const token = await tokens.issue({
		purpose: "email-link",
		timeToLiveMilliseconds: 60_000,
	});

	vi.advanceTimersByTime(60_000);

	expect((await tokens.consume(token, "email-link")).ok).toBe(false);
});

test("arbitrary strings are never valid tokens", async () => {
	const { tokens } = createFixture();

	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.string(), async (guess) => {
			expect((await tokens.consume(guess, "email-link")).ok).toBe(false);
		}),
	);
});

test("a token is still valid one millisecond before expiry", async () => {
	const { tokens } = createFixture();
	const token = await tokens.issue({
		purpose: "email-link",
		timeToLiveMilliseconds: 60_000,
	});

	vi.advanceTimersByTime(59_999);

	expect((await tokens.consume(token, "email-link")).ok).toBe(true);
});

test("every rejection reports the same error", async () => {
	const { tokens } = createFixture();
	const wrongPurpose = await tokens.issue({
		purpose: "oauth-state",
		timeToLiveMilliseconds: 60_000,
	});
	const expired = await tokens.issue({
		purpose: "email-link",
		timeToLiveMilliseconds: 1,
	});
	vi.advanceTimersByTime(1);

	const errors = await Promise.all([
		tokens.consume(wrongPurpose, "email-link"),
		tokens.consume(expired, "email-link"),
		tokens.consume("x".repeat(64), "email-link"),
		tokens.consume("short", "email-link"),
	]);

	expect(errors.map((result) => !result.ok && result.error)).toEqual(
		Array(4).fill("invalid-token"),
	);
});

test("malformed tokens never reach the store", async () => {
	const take = vi.fn();
	const tokens = createTokens({
		store: { put: async () => undefined, take },
	});

	await tokens.consume("x".repeat(65), "email-link");
	await tokens.consume("", "email-link");

	expect(take).not.toHaveBeenCalled();
});

test("a non-positive or non-finite time to live is a programming error", async () => {
	const { tokens } = createFixture();

	for (const timeToLiveMilliseconds of [
		Number.NaN,
		0,
		-1,
		Number.POSITIVE_INFINITY,
	]) {
		await expect(
			tokens.issue({ purpose: "email-link", timeToLiveMilliseconds }),
		).rejects.toThrow(RangeError);
	}
});

test("a record whose expiry the store lost is rejected", async () => {
	const memory = createMapTokenStore();
	const tokens = createTokens({
		store: {
			put: (hash, record) => memory.put(hash, record),
			take: async (hash) => {
				const record = await memory.take(hash);

				return (
					record && {
						...record,
						expiresAtMilliseconds: undefined as unknown as number,
					}
				);
			},
		},
	});
	const token = await tokens.issue({
		purpose: "email-link",
		timeToLiveMilliseconds: 60_000,
	});

	expect((await tokens.consume(token, "email-link")).ok).toBe(false);
});

test("inherited properties never replace missing options", async () => {
	Object.defineProperty(Object.prototype, "payload", {
		value: { admin: "true" },
		configurable: true,
	});

	try {
		const { tokens } = createFixture();
		const token = await tokens.issue({
			purpose: "email-link",
			timeToLiveMilliseconds: 60_000,
		});
		const result = await tokens.consume(token, "email-link");

		expect(result.ok && result.value).toEqual({});
	} finally {
		Reflect.deleteProperty(Object.prototype, "payload");
	}
});
