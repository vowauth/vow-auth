import type { EpochStore } from "@vow-auth/core";

/**
 * Runs a Lua script on Redis as `EVAL script keys.length ...keys ...args` and
 * returns the raw reply, so the store works with any client.
 *
 * @example
 * ioredis: `(script, keys, args) => redis.eval(script, keys.length, ...keys, ...args)`
 * node-redis: `(script, keys, args) => client.eval(script, { keys: [...keys], arguments: [...args] })`
 * Upstash: `(script, keys, args) => redis.eval(script, [...keys], [...args])`
 */
export type RedisScriptRunner = (
	script: string,
	keys: readonly string[],
	args: readonly string[],
) => Promise<unknown>;

/** Options of the Redis epoch store. */
export type RedisEpochStoreOptions = {
	readonly run: RedisScriptRunner;
};

const SERVER_NOW = `local time = redis.call("TIME")
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)`;

const READ_SCRIPT = `${SERVER_NOW}
if #KEYS == 0 then
	return { now, {} }
end
return { now, redis.call("MGET", unpack(KEYS)) }`;

const REVOKE_SCRIPT = `${SERVER_NOW}
local current = tonumber(redis.call("GET", KEYS[1]) or "0") or 0
local stamp = math.max(current + 1, now)
redis.call("SET", KEYS[1], string.format("%.0f", stamp), "PX", ARGV[1])
return stamp`;

const toNumber = (value: unknown): number => {
	if (typeof value === "number") {
		return value;
	}

	return typeof value === "string" ? Number(value) : Number.NaN;
};

/**
 * Epoch store on Redis 7+, Valkey 7.2+ or Upstash. Every time comes from the
 * server: both scripts call `TIME`, and key expiry runs on the same clock.
 * Keys of one chain share the `{tenant}` hash tag, so the store works in
 * Redis Cluster with one round trip per read.
 *
 * The deployment must keep revocations: `maxmemory-policy noeviction`, because
 * evicting a revocation revives its tokens, and persistence with AOF; with
 * `appendfsync everysec` a crash forgets up to one second of revocations.
 * Asynchronous replication means a failover forgets revocations within the
 * replication lag and moves to the replica's clock; use `WAIT` in the runner
 * or accept that bound.
 */
export function createRedisEpochStore(
	options: RedisEpochStoreOptions,
): EpochStore {
	const { run } = options;

	return {
		async read(keys) {
			const reply = await run(READ_SCRIPT, keys, []);

			if (
				!Array.isArray(reply) ||
				reply.length !== 2 ||
				!Array.isArray(reply[1])
			) {
				throw new Error("Unexpected reply from the epoch read script");
			}

			return {
				now: toNumber(reply[0]),
				stamps: reply[1].map((value: unknown) =>
					value === null ? 0 : toNumber(value),
				),
			};
		},
		async revoke(key, timeToLiveMilliseconds) {
			if (
				!Number.isFinite(timeToLiveMilliseconds) ||
				timeToLiveMilliseconds <= 0
			) {
				throw new RangeError(
					"timeToLiveMilliseconds must be a positive finite number",
				);
			}

			const stamp = toNumber(
				await run(
					REVOKE_SCRIPT,
					[key],
					[String(Math.ceil(timeToLiveMilliseconds))],
				),
			);

			if (!Number.isFinite(stamp)) {
				throw new Error("Unexpected reply from the epoch revoke script");
			}

			return stamp;
		},
	};
}
