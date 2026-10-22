/**
 * Runs a Lua script on Redis as `EVAL script keys.length ...keys ...args` and
 * returns the raw reply, so the stores work with any client.
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

/** The Lua prelude of every script: the server time in whole milliseconds. */
export const SERVER_NOW = `local time = redis.call("TIME")
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)`;

/** Reads a number from a reply that a client may return as a number or as a string. */
export const toNumber = (value: unknown): number => {
	if (typeof value === "number") {
		return value;
	}

	return typeof value === "string" ? Number(value) : Number.NaN;
};
