import { createRedisMeterStore } from "@vow-auth/adapter-redis";
import { slidingWindow } from "@vow-auth/core";
import { createMeter } from "@vow-auth/core/internal";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createConnection, sleep } from "./resp-connection.js";

const redisUrl = process.env.VOW_AUTH_REDIS_URL;
const MINUTE = 60_000;

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
	const serverNow = async (): Promise<number> => {
		const reply = await connection.command("TIME");

		if (!Array.isArray(reply)) {
			throw new Error("TIME must answer a list");
		}

		return Number(reply[0]) * 1_000 + Math.floor(Number(reply[1]) / 1_000);
	};

	beforeAll(async () => {
		connection = await createConnection(redisUrl ?? "");
	});

	afterAll(() => {
		connection.close();
	});

	test("requests pass up to the limit, and the counters live two intervals", async () => {
		const key = keyOf("limit");
		const results = [];

		for (let request = 0; request < 4; request += 1) {
			results.push(
				await store().consume({
					key,
					cost: 1,
					limit: 3,
					windowMilliseconds: MINUTE,
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
		expect(await connection.command("TYPE", key)).toBe("hash");
		expect(await connection.command("HGET", key, "c")).toBe("3");
		expect(await connection.command("HGET", key, "w")).toBe(String(MINUTE));

		const timeToLive = await connection.command("PTTL", key);

		expect(timeToLive).toBeGreaterThan(MINUTE);
		expect(timeToLive).toBeLessThanOrEqual(2 * MINUTE);
		expect(results[2]?.resetsAtMilliseconds).toBe(
			Number(await connection.command("HGET", key, "i")) * MINUTE + 2 * MINUTE,
		);
	});

	test("a refused request writes nothing", async () => {
		const key = keyOf("refusal");
		const consume = () =>
			store().consume({ key, cost: 1, limit: 1, windowMilliseconds: MINUTE });

		await consume();

		const before = await connection.command("HGETALL", key);

		for (let request = 0; request < 5; request += 1) {
			expect((await consume()).allowed).toBe(false);
		}

		expect(await connection.command("HGETALL", key)).toEqual(before);
	});

	test("a cost that does not fit counts nothing", async () => {
		const key = keyOf("cost");
		const consume = (cost: number) =>
			store().consume({ key, cost, limit: 3, windowMilliseconds: MINUTE });

		expect((await consume(2)).allowed).toBe(true);
		expect((await consume(2)).allowed).toBe(false);
		expect((await consume(1)).allowed).toBe(true);
		expect(await connection.command("HGET", key, "c")).toBe("3");
	});

	test("parallel requests are counted exactly once each", async () => {
		const key = keyOf("burst");
		const results = await Promise.all(
			Array.from({ length: 50 }, () =>
				store().consume({
					key,
					cost: 1,
					limit: 10,
					windowMilliseconds: MINUTE,
				}),
			),
		);

		expect(results.filter((result) => result.allowed)).toHaveLength(10);
		expect(await connection.command("HGET", key, "c")).toBe("10");
	});

	test("the same numbers as the core function: the previous interval fades by the formula", async () => {
		const key = keyOf("formula");
		const now = await serverNow();
		const index = Math.floor(now / MINUTE);

		await connection.command(
			"HSET",
			key,
			"w",
			String(MINUTE),
			"i",
			String(index - 1),
			"c",
			"42",
			"p",
			"0",
		);
		await connection.command("PEXPIRE", key, String(3 * MINUTE));

		const result = await store().consume({
			key,
			cost: 1,
			limit: 50,
			windowMilliseconds: MINUTE,
		});
		const after = await serverNow();
		const expected = (time: number) =>
			slidingWindow({
				state: {
					windowMilliseconds: MINUTE,
					index: index - 1,
					current: 42,
					previous: 0,
				},
				nowMilliseconds: time,
				windowMilliseconds: MINUTE,
				limit: 50,
				cost: 1,
			});

		expect(result.allowed).toBe(expected(after).allowed);
		expect(result.used).toBeGreaterThanOrEqual(
			Math.ceil(expected(after).estimate),
		);
		expect(result.used).toBeLessThanOrEqual(Math.ceil(expected(now).estimate));
	});

	test("a refused request is told the same retry moment as the core function computes", async () => {
		const key = keyOf("retry");
		const now = await serverNow();
		const index = Math.floor(now / MINUTE);
		const state = {
			windowMilliseconds: MINUTE,
			index,
			current: 4,
			previous: 5,
		};

		await connection.command(
			"HSET",
			key,
			"w",
			String(MINUTE),
			"i",
			String(index),
			"c",
			"4",
			"p",
			"5",
		);
		await connection.command("PEXPIRE", key, String(2 * MINUTE));

		const result = await store().consume({
			key,
			cost: 2,
			limit: 5,
			windowMilliseconds: MINUTE,
		});
		const expected = slidingWindow({
			state,
			nowMilliseconds: now,
			windowMilliseconds: MINUTE,
			limit: 5,
			cost: 2,
		});

		expect(result.allowed).toBe(false);
		expect(expected.allowed).toBe(false);
		expect(result.resetsAtMilliseconds).toBe(expected.retryAtMilliseconds);
	});

	test("the counter ends on the server and the key reads zero again", async () => {
		const key = keyOf("expiry");
		const consume = () =>
			store().consume({ key, cost: 1, limit: 1, windowMilliseconds: 100 });

		expect((await consume()).allowed).toBe(true);
		expect((await consume()).allowed).toBe(false);

		await sleep(450);

		expect(await connection.command("EXISTS", key)).toBe(0);
		expect((await consume()).allowed).toBe(true);
	});

	test("a refused request passes at the moment it was told", async () => {
		const key = keyOf("told");
		const consume = () =>
			store().consume({ key, cost: 1, limit: 1, windowMilliseconds: 150 });

		await consume();

		const refused = await consume();

		expect(refused.allowed).toBe(false);

		await sleep(
			Math.max(0, refused.resetsAtMilliseconds - (await serverNow())) + 40,
		);

		expect((await consume()).allowed).toBe(true);
	});

	test("a key used with another window length starts again", async () => {
		const key = keyOf("rule-change");

		await store().consume({
			key,
			cost: 1,
			limit: 1,
			windowMilliseconds: MINUTE,
		});

		expect(
			(
				await store().consume({
					key,
					cost: 1,
					limit: 1,
					windowMilliseconds: 2 * MINUTE,
				})
			).allowed,
		).toBe(true);
		expect(await connection.command("HGET", key, "w")).toBe(String(2 * MINUTE));
	});

	test("a field that is not a number fails the call", async () => {
		const key = keyOf("garbage");

		await connection.command(
			"HSET",
			key,
			"w",
			String(MINUTE),
			"i",
			"garbage",
			"c",
			"1",
			"p",
			"0",
		);

		await expect(
			store().consume({ key, cost: 1, limit: 5, windowMilliseconds: MINUTE }),
		).rejects.toThrow();
	});

	test("the core meter over Redis keeps scopes apart", async () => {
		const meter = createMeter({ store: store() });
		const rule = { limit: 1, windowMilliseconds: MINUTE };
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
