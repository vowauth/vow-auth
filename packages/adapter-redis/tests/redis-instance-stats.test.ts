import { createRedisInstanceStats } from "@vow-auth/adapter-redis";
import { expect, test } from "vitest";

const memoryInfo = "# Memory\nused_memory:1422848\nmaxmemory:2097152\n";
const statsInfo = "# Stats\ntotal_commands_processed:10\nevicted_keys:7\n";
const errorsInfo =
	"# Errorstats\nerrorstat_ERR:count=2\nerrorstat_OOM:count=5\n";

test("the instance numbers come from one read-only script call", async () => {
	const calls: { script: string; keys: readonly string[] }[] = [];
	const stats = createRedisInstanceStats({
		run: async (script, keys) => {
			calls.push({ script, keys });

			return [memoryInfo, statsInfo, errorsInfo, 42];
		},
	});

	expect(await stats.stats()).toEqual({
		entries: 42,
		usedBytes: 1_422_848,
		maximumBytes: 2_097_152,
		capacityRefusals: 5,
		evictions: 7,
	});
	expect(calls).toHaveLength(1);
	expect(calls[0]?.script).not.toMatch(/"(SET|HSET|INCRBY|DEL|PEXPIRE)"/);
});

test("no limit reads as unknown and no OOM errors as zero refusals", async () => {
	const stats = createRedisInstanceStats({
		run: async () => [
			"used_memory:100\nmaxmemory:0\n",
			"evicted_keys:0\n",
			"# Errorstats\n",
			0,
		],
	});

	expect(await stats.stats()).toEqual({
		entries: 0,
		usedBytes: 100,
		maximumBytes: undefined,
		capacityRefusals: 0,
		evictions: 0,
	});
});

test("an unexpected reply fails instead of reporting zeros", async () => {
	for (const reply of [null, "OK", [], [1, 2, 3, 4], ["a", "b", "c"]]) {
		await expect(
			createRedisInstanceStats({ run: async () => reply }).stats(),
		).rejects.toThrow("Unexpected reply");
	}
});
