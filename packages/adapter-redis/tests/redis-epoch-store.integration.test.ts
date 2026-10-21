import { once } from "node:events";
import { connect } from "node:net";
import { createRedisEpochStore } from "@vow-auth/adapter-redis";
import {
	createSealer,
	createSessionTokens,
	evaluatePolicy,
	issueSession,
} from "@vow-auth/core/internal";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

const redisUrl = process.env.VOW_AUTH_REDIS_URL;

type Reply = string | number | null | Error | readonly Reply[];

const encodeCommand = (parts: readonly string[]): string => {
	return `*${parts.length}\r\n${parts
		.map((part) => `$${Buffer.byteLength(part)}\r\n${part}\r\n`)
		.join("")}`;
};

const parseReply = (
	buffer: Buffer,
	offset: number,
): readonly [Reply, number] | undefined => {
	const lineEnd = buffer.indexOf("\r\n", offset);

	if (lineEnd < 0) {
		return undefined;
	}

	const type = buffer.toString("latin1", offset, offset + 1);
	const line = buffer.toString("utf8", offset + 1, lineEnd);
	const next = lineEnd + 2;

	if (type === "+") {
		return [line, next];
	}

	if (type === "-") {
		return [new Error(line), next];
	}

	if (type === ":") {
		return [Number(line), next];
	}

	const length = Number(line);

	if (length < 0) {
		return [null, next];
	}

	if (type === "$") {
		return buffer.length < next + length + 2
			? undefined
			: [buffer.toString("utf8", next, next + length), next + length + 2];
	}

	const items: Reply[] = [];
	let cursor = next;

	for (let index = 0; index < length; index += 1) {
		const parsed = parseReply(buffer, cursor);

		if (parsed === undefined) {
			return undefined;
		}

		items.push(parsed[0]);
		cursor = parsed[1];
	}

	return [items, cursor];
};

const createConnection = async (url: string) => {
	const { hostname, port } = new URL(url);
	const socket = connect(Number(port), hostname);
	const waiting: {
		readonly resolve: (reply: Reply) => void;
		readonly reject: (error: Error) => void;
	}[] = [];
	let buffer = Buffer.alloc(0);

	socket.on("data", (chunk: Buffer) => {
		buffer = Buffer.concat([buffer, chunk]);

		for (
			let parsed = parseReply(buffer, 0);
			parsed !== undefined;
			parsed = parseReply(buffer, 0)
		) {
			buffer = buffer.subarray(parsed[1]);
			const waiter = waiting.shift();

			if (parsed[0] instanceof Error) {
				waiter?.reject(parsed[0]);
			} else {
				waiter?.resolve(parsed[0]);
			}
		}
	});
	await once(socket, "connect");

	return {
		command: (...parts: string[]): Promise<Reply> => {
			return new Promise((resolve, reject) => {
				waiting.push({ resolve, reject });
				socket.write(encodeCommand(parts));
			});
		},
		close: () => {
			socket.end();
		},
	};
};

const sleep = (milliseconds: number) => {
	return new Promise((resolve) => setTimeout(resolve, milliseconds));
};

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
						timeToLiveMilliseconds: 60_000,
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
