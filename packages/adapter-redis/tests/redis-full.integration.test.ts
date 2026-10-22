import {
	createRedisEpochStore,
	createRedisInstanceStats,
	createRedisMeterStore,
} from "@vow-auth/adapter-redis";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createConnection } from "./resp-connection.js";

const normalUrl = process.env.VOW_AUTH_REDIS_URL;
const fullUrl = process.env.VOW_AUTH_REDIS_FULL_URL;

describe.runIf(normalUrl !== undefined)("the numbers of a live Redis", () => {
	let connection: Awaited<ReturnType<typeof createConnection>>;

	beforeAll(async () => {
		connection = await createConnection(normalUrl ?? "");
	});

	afterAll(() => {
		connection.close();
	});

	test("the instance stats read the real numbers", async () => {
		const stats = await createRedisInstanceStats({
			run: (script, keys, args) =>
				connection.command(
					"EVAL",
					script,
					String(keys.length),
					...keys,
					...args,
				),
		}).stats();

		expect(stats.usedBytes).toBeGreaterThan(0);
		expect(stats.entries).toBe(await connection.command("DBSIZE"));
		expect(stats.evictions).toBe(0);
		expect(typeof stats.capacityRefusals).toBe("number");
	});
});

describe.runIf(fullUrl !== undefined)(
	"a Redis that has run out of memory (maxmemory with noeviction)",
	() => {
		let connection: Awaited<ReturnType<typeof createConnection>>;
		const run = (
			script: string,
			keys: readonly string[],
			args: readonly string[],
		) =>
			connection.command("EVAL", script, String(keys.length), ...keys, ...args);

		beforeAll(async () => {
			connection = await createConnection(fullUrl ?? "");
			await connection.command(
				"EVAL",
				"for i=1,200000 do redis.pcall('SET','fill:'..i, string.rep('x',200)) end return 1",
				"0",
			);
		});

		afterAll(() => {
			connection.close();
		});

		test("reads and issuing keep working, a revocation cannot be written", async () => {
			const epochs = createRedisEpochStore({ run });

			expect((await epochs.read(["{acme}:user:alice"])).stamps).toEqual([0]);
			await expect(epochs.revoke("{acme}:user:alice", 60_000)).rejects.toThrow(
				/OOM/,
			);
		});

		test("a request that must be counted fails the call and is not let through", async () => {
			const meter = createRedisMeterStore({ run });
			const key = `{full-${crypto.randomUUID()}}:meter:x`;

			await expect(
				meter.consume({ key, cost: 1, limit: 1, windowMilliseconds: 60_000 }),
			).rejects.toThrow(/OOM/);
		});

		test("the stats still answer and show the refused writes", async () => {
			const stats = await createRedisInstanceStats({ run }).stats();

			expect(stats.capacityRefusals).toBeGreaterThan(0);
			expect(stats.maximumBytes).toBeGreaterThan(0);
			expect(stats.usedBytes).toBeGreaterThan(stats.maximumBytes ?? 0);
			expect(stats.evictions).toBe(0);
		});
	},
);
