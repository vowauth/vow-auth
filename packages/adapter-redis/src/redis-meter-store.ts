import type { MeterStore } from "@vow-auth/core";
import {
	type RedisScriptRunner,
	SERVER_NOW,
	toNumber,
} from "./redis-script-runner.js";

/** Options of the Redis meter store. */
export type RedisMeterStoreOptions = {
	readonly run: RedisScriptRunner;
};

const CONSUME_SCRIPT = `${SERVER_NOW}
local cost = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local used = tonumber(redis.call("GET", KEYS[1]) or "0")
local remaining = redis.call("PTTL", KEYS[1])
local allowed = 0
if used + cost <= limit then
	used = redis.call("INCRBY", KEYS[1], cost)
	allowed = 1
end
if remaining < 0 then
	redis.call("PEXPIRE", KEYS[1], window)
	remaining = window
end
return { allowed, used, now + remaining }`;

/**
 * Meter store on Redis 7+, Valkey 7.2+ or Upstash. One script call counts a
 * request: it reads the server time, checks the counter against the limit,
 * counts the cost only when it fits, and starts the window on the first
 * counted request. A counter that has no expiry, left by something else, gets
 * a window instead of denying for ever. A value that is not a number makes the
 * script fail, and so the call: nothing is let through on a guess. The key
 * keeps the `{tenant}` hash tag of the core, so the store works in Redis
 * Cluster.
 *
 * The deployment must not forget counters early: `maxmemory-policy noeviction`,
 * because evicting a counter resets its limit. Losing data (a crash without
 * persistence, a failover within the replication lag) resets limits too; it
 * loosens them for at most one window and opens no access.
 */
export function createRedisMeterStore(
	options: RedisMeterStoreOptions,
): MeterStore {
	const { run } = options;

	return {
		async consume(input) {
			const reply = await run(
				CONSUME_SCRIPT,
				[input.key],
				[
					String(input.cost),
					String(input.limit),
					String(Math.ceil(input.windowMilliseconds)),
				],
			);

			if (!Array.isArray(reply) || reply.length !== 3) {
				throw new Error("Unexpected reply from the meter consume script");
			}

			const [allowed, used, resetsAtMilliseconds] = reply.map(toNumber);

			if (
				(allowed !== 0 && allowed !== 1) ||
				used === undefined ||
				!Number.isFinite(used) ||
				resetsAtMilliseconds === undefined ||
				!Number.isFinite(resetsAtMilliseconds)
			) {
				throw new Error("Unexpected reply from the meter consume script");
			}

			return {
				allowed: allowed === 1,
				used,
				remaining: Math.max(0, input.limit - used),
				resetsAtMilliseconds,
			};
		},
	};
}
