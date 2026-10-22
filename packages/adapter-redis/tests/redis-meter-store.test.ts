import { createRedisMeterStore } from "@vow-auth/adapter-redis";
import { expect, test } from "vitest";

const createRecordingRunner = (reply: unknown) => {
	const calls: {
		readonly script: string;
		readonly keys: readonly string[];
		readonly args: readonly string[];
	}[] = [];

	return {
		calls,
		run: async (
			script: string,
			keys: readonly string[],
			args: readonly string[],
		) => {
			calls.push({ script, keys, args });

			return reply;
		},
	};
};

const input = {
	key: "{acme}:meter:email-link:alice",
	cost: 2,
	limit: 5,
	windowMilliseconds: 1_000.2,
};

test("a request is one script call with the key, the cost, the limit and a whole-millisecond window", async () => {
	const runner = createRecordingRunner([1, 2, 1_791_972_001_000]);
	const store = createRedisMeterStore({ run: runner.run });

	expect(await store.consume(input)).toEqual({
		allowed: true,
		used: 2,
		remaining: 3,
		resetsAtMilliseconds: 1_791_972_001_000,
	});
	expect(runner.calls).toHaveLength(1);
	expect(runner.calls[0]?.keys).toEqual(["{acme}:meter:email-link:alice"]);
	expect(runner.calls[0]?.args).toEqual(["2", "5", "1001"]);
	expect(runner.calls[0]?.script).toContain('redis.call("TIME")');
	expect(runner.calls[0]?.script).toContain('redis.call("HMGET"');
	expect(runner.calls[0]?.script).toContain('redis.call("HSET"');
	expect(runner.calls[0]?.script).toContain('redis.call("PEXPIRE"');
});

test("a refusal reports what is used and counts nothing more", async () => {
	const store = createRedisMeterStore({
		run: createRecordingRunner([0, 5, 1_791_972_001_000]).run,
	});

	expect(await store.consume(input)).toEqual({
		allowed: false,
		used: 5,
		remaining: 0,
		resetsAtMilliseconds: 1_791_972_001_000,
	});
});

test("replies that clients return as strings are read as numbers", async () => {
	const store = createRedisMeterStore({
		run: createRecordingRunner(["1", "1", "1791972001000"]).run,
	});

	expect((await store.consume(input)).allowed).toBe(true);
});

test("an unexpected reply fails the call instead of letting the request through", async () => {
	for (const reply of [
		null,
		"OK",
		[],
		[1, 2],
		[2, 1, 1_000],
		["yes", 1, 1_000],
		[1, "garbage", 1_000],
		[1, 1, null],
		{ allowed: 1 },
	]) {
		await expect(
			createRedisMeterStore({ run: createRecordingRunner(reply).run }).consume(
				input,
			),
		).rejects.toThrow("Unexpected reply");
	}
});

test("a failing runner fails the call", async () => {
	const store = createRedisMeterStore({
		run: async () => {
			throw new Error("connection refused");
		},
	});

	await expect(store.consume(input)).rejects.toThrow("connection refused");
});
