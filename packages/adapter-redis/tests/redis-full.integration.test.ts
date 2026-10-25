import { createRedisMeterStore } from "@vow-auth/adapter-redis";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createConnection } from "./resp-connection.js";

const fullUrl = process.env.VOW_AUTH_REDIS_FULL_URL;

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

		test("a request that must be counted fails the call and is not let through", async () => {
			const meter = createRedisMeterStore({ run });
			const key = `{full-${crypto.randomUUID()}}:meter:x`;

			await expect(
				meter.consume({ key, cost: 1, limit: 1, windowMilliseconds: 60_000 }),
			).rejects.toThrow(/OOM/);
		});
	},
);
