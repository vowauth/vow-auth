import { createRedisMeterStore } from "@vow-auth/adapter-redis";
import { createMeter } from "@vow-auth/core/internal";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createConnection, sleep } from "./resp-connection.js";

const redisUrl = process.env.VOW_AUTH_REDIS_URL;

describe.runIf(redisUrl !== undefined)("the meter on a live Redis", () => {
	let connection: Awaited<ReturnType<typeof createConnection>>;
	const tenant = `vow-test-${crypto.randomUUID()}`;
	const keyOf = (name: string) => `{${tenant}}:meter:${name}`;
	const store = () => {
		return createRedisMeterStore({
			run: (script, keys, args) =>
				connection.command(
					"EVAL",
					script,
					String(keys.length),
					...keys,
					...args,
				),
		});
	};

	beforeAll(async () => {
		connection = await createConnection(redisUrl ?? "");
	});

	afterAll(() => {
		connection.close();
	});

	test("requests pass up to the limit with a window that Redis expires", async () => {
		const key = keyOf("limit");
		const results = [];

		for (let request = 0; request < 4; request += 1) {
			results.push(
				await store().consume({
					key,
					cost: 1,
					limit: 3,
					windowMilliseconds: 60_000,
				}),
			);
		}

		expect(results.map((result) => result.allowed)).toEqual([
			true,
			true,
			true,
			false,
		]);
		expect(results.map((result) => result.used)).toEqual([1, 2, 3, 3]);
		expect(results[3]?.remaining).toBe(0);
		expect(await connection.command("GET", key)).toBe("3");

		const timeToLive = await connection.command("PTTL", key);

		expect(timeToLive).toBeGreaterThan(59_000);
		expect(timeToLive).toBeLessThanOrEqual(60_000);
		expect(results[0]?.resetsAtMilliseconds).toBe(
			results[3]?.resetsAtMilliseconds,
		);
	});

	test("a cost that does not fit counts nothing", async () => {
		const key = keyOf("cost");
		const consume = (cost: number) =>
			store().consume({ key, cost, limit: 3, windowMilliseconds: 60_000 });

		expect((await consume(2)).allowed).toBe(true);
		expect((await consume(2)).allowed).toBe(false);
		expect((await consume(1)).allowed).toBe(true);
		expect(await connection.command("GET", key)).toBe("3");
	});

	test("parallel requests are counted exactly once each", async () => {
		const key = keyOf("burst");
		const results = await Promise.all(
			Array.from({ length: 50 }, () =>
				store().consume({
					key,
					cost: 1,
					limit: 10,
					windowMilliseconds: 60_000,
				}),
			),
		);

		expect(results.filter((result) => result.allowed)).toHaveLength(10);
		expect(await connection.command("GET", key)).toBe("10");
	});

	test("the window ends on the server and the count starts again", async () => {
		const key = keyOf("window");
		const consume = () =>
			store().consume({ key, cost: 1, limit: 1, windowMilliseconds: 100 });

		expect((await consume()).allowed).toBe(true);
		expect((await consume()).allowed).toBe(false);

		await sleep(250);

		expect((await consume()).allowed).toBe(true);
	});

	test("a counter without an expiry gets a window instead of denying for ever", async () => {
		const key = keyOf("healing");

		await connection.command("SET", key, "5");

		const result = await store().consume({
			key,
			cost: 1,
			limit: 5,
			windowMilliseconds: 60_000,
		});

		expect(result.allowed).toBe(false);
		expect(await connection.command("PTTL", key)).toBeGreaterThan(0);
	});

	test("a value that is not a number fails the call", async () => {
		const key = keyOf("garbage");

		await connection.command("SET", key, "garbage");

		await expect(
			store().consume({ key, cost: 1, limit: 5, windowMilliseconds: 60_000 }),
		).rejects.toThrow();
	});

	test("the core meter over Redis keeps scopes apart and shares the window", async () => {
		const meter = createMeter({ store: store() });
		const rule = { limit: 1, windowMilliseconds: 60_000 };
		const scope = { tenant, actor: "alice", resource: "email-link" };

		expect((await meter.consume(scope, rule)).ok).toBe(true);
		expect((await meter.consume(scope, rule)).ok).toBe(false);
		expect((await meter.consume({ ...scope, actor: "bob" }, rule)).ok).toBe(
			true,
		);
		expect(
			(await meter.consume({ ...scope, tenant: `${tenant}-other` }, rule)).ok,
		).toBe(true);
	});
});
