import { createMemoryOutboxStore } from "@vow-auth/adapter-memory";
import {
	createEmit,
	createOutboxWorker,
	type OutboxHandler,
	type OutboxRecord,
} from "@vow-auth/core";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const RETRY_DELAY = 1_000;
const LEASE = 5_000;

const createFixture = (
	handlers: Readonly<Record<string, OutboxHandler>>,
	maximumAttempts = 3,
) => {
	const store = createMemoryOutboxStore();
	const emit = createEmit(store);
	const worker = createOutboxWorker({
		store,
		handlers,
		batchSize: 10,
		leaseMilliseconds: LEASE,
		retryDelayMilliseconds: RETRY_DELAY,
		maximumAttempts,
	});

	return { emit, store, worker };
};

const mustEmit = async (
	emit: ReturnType<typeof createEmit>,
	type: string,
	payload: Record<string, string> = {},
): Promise<string> => {
	const result = await emit({ type, payload });

	if (!result.ok) {
		throw new Error("a valid event must be recorded");
	}

	return result.value;
};

test("emit records the event and calls no handler", async () => {
	const handler = vi.fn(async () => undefined);
	const { emit, store } = createFixture({ "email.send": handler });

	await mustEmit(emit, "email.send", { to: "a@example.com" });

	expect(handler).not.toHaveBeenCalled();
	expect(store.pending()).toBe(1);
});

test("a worker delivers the event with its id and removes it", async () => {
	const received: OutboxRecord[] = [];
	const { emit, store, worker } = createFixture({
		"email.send": async (event) => {
			received.push(event);
		},
	});
	const id = await mustEmit(emit, "email.send", { to: "a@example.com" });

	const summary = await worker.runOnce();

	expect(summary).toEqual({ completed: 1, retried: 0, buried: 0 });
	expect(received).toEqual([
		{
			id,
			type: "email.send",
			payload: { to: "a@example.com" },
			attempts: 1,
		},
	]);
	expect(store.pending()).toBe(0);
});

test("a failing recipient never breaks emit, and the event is retried after the delay", async () => {
	let healthy = false;
	const { emit, worker } = createFixture({
		"email.send": async () => {
			if (!healthy) {
				throw new Error("mail provider is down");
			}
		},
	});

	await mustEmit(emit, "email.send");

	expect(await worker.runOnce()).toEqual({
		completed: 0,
		retried: 1,
		buried: 0,
	});
	expect(await worker.runOnce()).toEqual({
		completed: 0,
		retried: 0,
		buried: 0,
	});

	healthy = true;
	vi.setSystemTime(1_000 + RETRY_DELAY);

	expect(await worker.runOnce()).toEqual({
		completed: 1,
		retried: 0,
		buried: 0,
	});
});

test("an event that keeps failing is buried after the maximum attempts", async () => {
	const handler = vi.fn(async () => {
		throw new Error("always fails");
	});
	const { emit, store, worker } = createFixture({ "email.send": handler }, 3);
	const id = await mustEmit(emit, "email.send");

	for (let run = 0; run < 3; run += 1) {
		await worker.runOnce();
		vi.setSystemTime(Date.now() + RETRY_DELAY);
	}

	expect(handler).toHaveBeenCalledTimes(3);
	expect(store.pending()).toBe(0);
	expect(store.buried().map((record) => record.id)).toEqual([id]);
});

test("an event without a handler is buried at once, whatever its type is called", async () => {
	const { emit, store, worker } = createFixture({});

	for (const type of ["unknown", "constructor", "__proto__", "toString"]) {
		await mustEmit(emit, type);
	}

	expect(await worker.runOnce()).toEqual({
		completed: 0,
		retried: 0,
		buried: 4,
	});
	expect(store.buried()).toHaveLength(4);
});

test("workers running together handle each event exactly once", async () => {
	const handled: string[] = [];
	const { emit, store, worker } = createFixture({
		"email.send": async (event) => {
			handled.push(event.id);
		},
	});
	const ids = new Set<string>();

	for (let index = 0; index < 25; index += 1) {
		ids.add(await mustEmit(emit, "email.send"));
	}

	await Promise.all(Array.from({ length: 8 }, () => worker.runOnce()));
	await Promise.all(Array.from({ length: 8 }, () => worker.runOnce()));
	await Promise.all(Array.from({ length: 8 }, () => worker.runOnce()));

	expect(handled).toHaveLength(25);
	expect(new Set(handled)).toEqual(ids);
	expect(store.pending()).toBe(0);
});

test("an event of a crashed worker is delivered after its lease, and the stale worker cannot undo it", async () => {
	const { emit, store, worker } = createFixture({
		"email.send": async () => undefined,
	});

	await mustEmit(emit, "email.send");
	const [crashed] = await store.claim({ limit: 1, leaseMilliseconds: LEASE });

	if (crashed === undefined) {
		throw new Error("the event must be claimable");
	}

	expect(await worker.runOnce()).toEqual({
		completed: 0,
		retried: 0,
		buried: 0,
	});

	vi.setSystemTime(1_000 + LEASE);
	const [reclaimed] = await store.claim({ limit: 1, leaseMilliseconds: LEASE });

	expect(reclaimed?.attempts).toBe(2);

	await store.complete(crashed);
	await store.bury(crashed);
	await store.release(crashed, 0);

	expect(store.pending()).toBe(1);
	expect(store.buried()).toEqual([]);

	if (reclaimed !== undefined) {
		await store.complete(reclaimed);
	}

	expect(store.pending()).toBe(0);
});

test("malformed events are refused and record nothing", async () => {
	const { store } = createFixture({});
	const emit = createEmit(store);

	for (const event of [
		null,
		"event",
		[],
		{},
		{ type: "" },
		{ type: 1 },
		{ type: "a", extra: "x" },
		{ type: "a", payload: "x" },
		{ type: "a", payload: [] },
		{ type: "a", payload: { count: 1 } },
		{ type: "a", payload: { nested: { x: "y" } } },
	]) {
		const result = await Reflect.apply(emit, undefined, [event]);

		expect(result.ok, JSON.stringify(event)).toBe(false);
	}

	expect(store.pending()).toBe(0);
});

test("the payload is copied, so the caller cannot change a recorded event", async () => {
	const received: OutboxRecord[] = [];
	const { emit, worker } = createFixture({
		"email.send": async (event) => {
			received.push(event);
		},
	});
	const payload = { to: "a@example.com" };

	await emit({ type: "email.send", payload });
	payload.to = "attacker@example.com";
	await worker.runOnce();

	expect(received[0]?.payload).toEqual({ to: "a@example.com" });
});

test("inherited properties never supply the payload", async () => {
	Object.defineProperty(Object.prototype, "payload", {
		value: { admin: "true" },
		configurable: true,
	});

	try {
		const received: OutboxRecord[] = [];
		const { emit, worker } = createFixture({
			"email.send": async (event) => {
				received.push(event);
			},
		});

		await emit({ type: "email.send" });
		await worker.runOnce();

		expect(received[0]?.payload).toEqual({});
	} finally {
		Reflect.deleteProperty(Object.prototype, "payload");
	}
});

test("the worker refuses unusable options", () => {
	const store = createMemoryOutboxStore();
	const valid = {
		store,
		handlers: {},
		batchSize: 1,
		leaseMilliseconds: 1,
		retryDelayMilliseconds: 1,
		maximumAttempts: 1,
	};

	for (const broken of [
		{ batchSize: 0 },
		{ batchSize: 1.5 },
		{ maximumAttempts: 0 },
		{ leaseMilliseconds: 0 },
		{ leaseMilliseconds: Number.NaN },
		{ retryDelayMilliseconds: -1 },
		{ retryDelayMilliseconds: Number.POSITIVE_INFINITY },
	]) {
		expect(() => createOutboxWorker({ ...valid, ...broken })).toThrow(
			RangeError,
		);
	}
});
