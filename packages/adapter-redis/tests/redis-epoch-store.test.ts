import { createRedisEpochStore } from "@vow-auth/adapter-redis";
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

test("a read is one script call that takes the time and every key", async () => {
	const runner = createRecordingRunner([
		1_791_972_000_000,
		["1791882000000", null],
	]);
	const epochs = createRedisEpochStore({ run: runner.run });

	const reading = await epochs.read([
		"{acme}:user:alice",
		"{acme}:device:laptop",
	]);

	expect(reading).toEqual({
		now: 1_791_972_000_000,
		stamps: [1_791_882_000_000, 0],
	});
	expect(runner.calls).toHaveLength(1);
	expect(runner.calls[0]?.keys).toEqual([
		"{acme}:user:alice",
		"{acme}:device:laptop",
	]);
	expect(runner.calls[0]?.script).toContain('redis.call("TIME")');
	expect(runner.calls[0]?.script).toContain('redis.call("MGET"');
});

test("a revocation is one script call with the server time and a whole-millisecond time to live", async () => {
	const runner = createRecordingRunner(1_791_972_000_001);
	const epochs = createRedisEpochStore({ run: runner.run });

	expect(await epochs.revoke("{acme}:user:alice", 1_000.2)).toBe(
		1_791_972_000_001,
	);
	expect(runner.calls[0]?.keys).toEqual(["{acme}:user:alice"]);
	expect(runner.calls[0]?.args).toEqual(["1001"]);
	expect(runner.calls[0]?.script).toContain('redis.call("TIME")');
	expect(runner.calls[0]?.script).toContain("math.max(current + 1, now)");
});

test("an unexpected reply fails loudly instead of reading as never revoked", async () => {
	for (const reply of [null, "OK", [1], [1, "not a list"], { now: 1 }]) {
		await expect(
			createRedisEpochStore({ run: createRecordingRunner(reply).run }).read([
				"{acme}:user:alice",
			]),
		).rejects.toThrow("Unexpected reply");
	}

	await expect(
		createRedisEpochStore({ run: createRecordingRunner(null).run }).revoke(
			"{acme}:user:alice",
			1_000,
		),
	).rejects.toThrow("Unexpected reply");
	await expect(
		createRedisEpochStore({ run: createRecordingRunner(1).run }).revoke(
			"{acme}:user:alice",
			0,
		),
	).rejects.toThrow(RangeError);
});

test("a stored value that is not a number reaches the core as not finite", async () => {
	const epochs = createRedisEpochStore({
		run: createRecordingRunner([1_000, ["garbage"]]).run,
	});

	expect(
		Number.isFinite((await epochs.read(["{acme}:user:alice"])).stamps[0]),
	).toBe(false);
});
