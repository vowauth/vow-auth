import type { StoreStats } from "@vow-auth/core";
import type { RedisScriptRunner } from "./redis-script-runner.js";

/** Options of the Redis instance stats. */
export type RedisInstanceStatsOptions = {
	readonly run: RedisScriptRunner;
};

/** Reads the numbers of the Redis instance the runner talks to. */
export type RedisInstanceStats = {
	stats(): Promise<StoreStats>;
};

const STATS_SCRIPT = `return {
	redis.call("INFO", "memory"),
	redis.call("INFO", "stats"),
	redis.call("INFO", "errorstats"),
	redis.call("DBSIZE")
}`;

const fieldOf = (info: string, name: string): number | undefined => {
	for (const line of info.split("\n")) {
		const separator = line.indexOf(":");

		if (separator > 0 && line.slice(0, separator) === name) {
			const value = Number.parseFloat(line.slice(separator + 1));

			return Number.isFinite(value) ? value : undefined;
		}
	}

	return undefined;
};

const countOfError = (info: string, errorName: string): number => {
	for (const line of info.split("\n")) {
		if (line.startsWith(`errorstat_${errorName}:`)) {
			const count = Number.parseFloat(line.slice(line.indexOf("count=") + 6));

			return Number.isFinite(count) ? count : 0;
		}
	}

	return 0;
};

/**
 * The numbers of a Redis instance for the operator's metrics: memory in use,
 * the `maxmemory` limit, keys evicted, and writes refused with `OOM`. They
 * describe the whole instance, not one store: give epochs their own instance
 * (see `createRedisEpochStore`) and this reads that instance alone. Call it
 * when the metrics collector asks, for example on every scrape; it costs one
 * script call and the core never calls it on the request path. The script only
 * reads, so it still answers when the instance refuses writes.
 */
export function createRedisInstanceStats(
	options: RedisInstanceStatsOptions,
): RedisInstanceStats {
	const { run } = options;

	return {
		async stats() {
			const reply = await run(STATS_SCRIPT, [], []);

			if (
				!Array.isArray(reply) ||
				reply.length !== 4 ||
				reply.slice(0, 3).some((part: unknown) => typeof part !== "string")
			) {
				throw new Error("Unexpected reply from the stats script");
			}

			const [memory, statistics, errors, size] = reply;
			const maximumBytes = fieldOf(memory, "maxmemory");

			return {
				entries: typeof size === "number" ? size : undefined,
				usedBytes: fieldOf(memory, "used_memory"),
				maximumBytes: maximumBytes === 0 ? undefined : maximumBytes,
				capacityRefusals: countOfError(errors, "OOM"),
				evictions: fieldOf(statistics, "evicted_keys"),
			};
		},
	};
}
