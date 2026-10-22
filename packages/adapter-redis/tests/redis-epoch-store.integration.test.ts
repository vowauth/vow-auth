import { createRedisEpochStore } from "@vow-auth/adapter-redis";
import {
	createSealer,
	createSessionTokens,
	evaluatePolicy,
	issueSession,
} from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/store-contracts";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { createConnection, sleep } from "./resp-connection.js";

const redisUrl = process.env.VOW_AUTH_REDIS_URL;

describe.runIf(redisUrl !== undefined)("on a live Redis", () => {
	let connection: Awaited<ReturnType<typeof createConnection>>;
	const prefix = `{vow-test-${crypto.randomUUID()}}`;
	const epochs = () => {
		return createRedisEpochStore({
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

	test("a key never revoked reads as 0 next to the server time", async () => {
		const reading = await epochs().read([
			`${prefix}:user:never`,
			`${prefix}:device:never`,
		]);

		expect(reading.stamps).toEqual([0, 0]);
		expect(Number.isSafeInteger(reading.now)).toBe(true);
		expect(reading.now).toBeGreaterThan(1_700_000_000_000);
		expect(await epochs().read([])).toEqual({
			now: expect.any(Number),
			stamps: [],
		});
	});

	test("a revocation stores a whole-number stamp at server time with its time to live", async () => {
		const key = `${prefix}:user:alice`;
		const before = (await epochs().read([])).now;
		const stamp = await epochs().revoke(key, 60_000.5);
		const reading = await epochs().read([key]);

		expect(stamp).toBeGreaterThanOrEqual(before);
		expect(reading.stamps).toEqual([stamp]);
		expect(await connection.command("GET", key)).toMatch(/^\d+$/);

		const timeToLive = await connection.command("PTTL", key);
		expect(timeToLive).toBeGreaterThan(59_000);
		expect(timeToLive).toBeLessThanOrEqual(60_001);
	});

	test("parallel revocations of one key give strictly increasing stamps", async () => {
		const key = `${prefix}:user:burst`;
		const stamps = await Promise.all(
			Array.from({ length: 20 }, () => epochs().revoke(key, 60_000)),
		);

		expect(new Set(stamps).size).toBe(20);
		expect((await epochs().read([key])).stamps).toEqual([Math.max(...stamps)]);
	});

	test("a revocation expires on the server and reads as 0 again", async () => {
		const key = `${prefix}:session:short`;
		await epochs().revoke(key, 50);
		await sleep(150);

		expect((await epochs().read([key])).stamps).toEqual([0]);
	});

	test("a revocation over a value that is not a number still raises the stamp", async () => {
		const key = `${prefix}:user:garbage`;
		await connection.command("SET", key, "garbage");
		const now = (await epochs().read([])).now;

		expect(await epochs().revoke(key, 60_000)).toBeGreaterThanOrEqual(now);
	});

	test("session tokens over Redis revoke instantly and cascade", async () => {
		const tenant = `tenant-${crypto.randomUUID()}`;
		const sessionTokens = createSessionTokens({
			sealer: createSealer({
				secrets: [
					{ version: 1, value: "session-secret-0123456789abcdefghijk" },
				],
			}),
			epochs: epochs(),
			maximumLifeTimeMilliseconds: 60_000,
		});
		const issueFor = async (subject: string) => {
			const session = issueSession(
				await evaluatePolicy(subject, () => "allow"),
			);
			const token = session.ok
				? await sessionTokens.issue(session.value, {
						tenant,
						device: "laptop",
						timeToLive: durationOf(60_000),
						methods: ["test"],
					})
				: undefined;

			return token?.ok ? token.value : "";
		};
		const alice = await issueFor("alice");
		const bob = await issueFor("bob");

		expect((await sessionTokens.verify(alice)).ok).toBe(true);

		await sessionTokens.revoke({ tenant, scope: "user", id: "alice" });
		expect((await sessionTokens.verify(alice)).ok).toBe(false);
		expect((await sessionTokens.verify(bob)).ok).toBe(true);

		const aliceAgain = await issueFor("alice");
		expect((await sessionTokens.verify(aliceAgain)).ok).toBe(true);

		await sessionTokens.revoke({ tenant, scope: "tenant" });
		expect((await sessionTokens.verify(aliceAgain)).ok).toBe(false);
		expect((await sessionTokens.verify(bob)).ok).toBe(false);
	});
});
