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
local index = math.floor(now / window)
local stored = redis.call("HMGET", KEYS[1], "w", "i", "c", "p")
local storedWindow = nil
local storedIndex = nil
local current = 0
local previous = 0
if stored[2] then
	storedWindow = tonumber(stored[1])
	storedIndex = tonumber(stored[2])
	current = tonumber(stored[3])
	previous = tonumber(stored[4])
	if not (storedWindow and storedIndex and current and previous) then
		return redis.error_reply("corrupt meter counter")
	end
end
local rolledIndex = index
if storedWindow ~= window then
	current = 0
	previous = 0
elseif storedIndex >= index then
	rolledIndex = storedIndex
elseif storedIndex == index - 1 then
	previous = current
	current = 0
else
	current = 0
	previous = 0
end
local intervalStart = rolledIndex * window
local elapsed = math.min(window, math.max(0, now - intervalStart))
local estimate = previous * (window - elapsed) / window + current
if estimate + cost <= limit + 1e-9 then
	current = current + cost
	estimate = estimate + cost
	redis.call("HSET", KEYS[1], "w", window, "i", rolledIndex, "c", current, "p", previous)
	local expiresAt = (rolledIndex + 2) * window
	redis.call("PEXPIRE", KEYS[1], expiresAt - now)
	return { 1, math.ceil(estimate), expiresAt }
end
local room = limit - cost
local retry = nil
if current <= room and previous > 0 then
	local wait = math.max(0, window - window * (room - current) / previous)
	if wait < window then
		retry = intervalStart + wait
	end
end
if retry == nil then
	retry = intervalStart + window
	if current > room then
		retry = retry + window - window * room / current
	end
end
return { 0, math.ceil(estimate), math.ceil(retry) }`;

/**
 * Meter store on Redis 7+, Valkey 7.2+ or Upstash. It decides as the core's
 * `slidingWindow` does, in one script call: the key is a hash with the window
 * length, the interval index and the counts of the current and previous
 * interval, so the sliding window approximation of Cloudflare's rate limiting
 * costs one round trip and one key, and the key keeps the `{tenant}` hash tag
 * of the core, so the store works in Redis Cluster. All times come from the
 * server's `TIME`; a counted request refreshes the expiry to the end of the
 * next interval, after which the key reads zero and disappears. A refused
 * request writes nothing. A field that is not a number makes the script fail,
 * and so the call: nothing is let through on a guess.
 *
 * The deployment must not forget counters early: `maxmemory-policy noeviction`,
 * because evicting a counter resets its limit. Losing data (a crash without
 * persistence, a failover within the replication lag) resets limits too; it
 * loosens them for at most two intervals and opens no access.
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
