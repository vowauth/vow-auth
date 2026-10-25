import { createRedisMeterStore } from "@vow-auth/adapter-redis";
import { meterStoreContract, type StoreClock } from "@vow-auth/store-contracts";
import { afterAll, beforeAll, describe } from "vitest";
import { createConnection, sleep } from "./resp-connection.js";

const redisUrl = process.env.VOW_AUTH_REDIS_URL;

describe.runIf(redisUrl !== undefined)("redis", () => {
	let connection: Awaited<ReturnType<typeof createConnection>>;

	beforeAll(async () => {
		connection = await createConnection(redisUrl ?? "");
	});

	afterAll(() => {
		connection.close();
	});

	const run = (
		script: string,
		keys: readonly string[],
		args: readonly string[],
	) =>
		connection.command("EVAL", script, String(keys.length), ...keys, ...args);

	const clock: StoreClock = {
		now: async () => {
			const reply = await connection.command("TIME");

			if (!Array.isArray(reply)) {
				throw new Error("TIME must answer a list");
			}

			return Number(reply[0]) * 1_000 + Math.floor(Number(reply[1]) / 1_000);
		},
		advance: async (milliseconds) => {
			await sleep(milliseconds);
		},
	};

	meterStoreContract("redis", {
		create: () => createRedisMeterStore({ run }),
		clock,
	});
});
