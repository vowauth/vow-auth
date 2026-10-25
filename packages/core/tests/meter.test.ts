import { createMemoryMeterStore } from "@vow-auth/adapter-memory";
import type { AuditRecord, AuditSink, MeterStore } from "@vow-auth/core";
import { defineMeterRule } from "@vow-auth/core";
import { createMeter } from "@vow-auth/core/internal";
import { meterRuleOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const RULE = meterRuleOf({ limit: 3, windowMilliseconds: 1_000 });
const SCOPE = { tenant: "acme", actor: "alice", resource: "email-link" };

const createFixture = (audit?: AuditSink) => {
	const records: AuditRecord[] = [];
	const collecting: AuditSink = async (record) => {
		records.push(record);
	};
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		audit: audit ?? collecting,
	});

	return { meter, records };
};

test("requests pass up to the limit, then are refused until the rate has eased", async () => {
	const { meter } = createFixture();
	const results = [];

	for (let request = 0; request < 4; request += 1) {
		results.push(await meter.consume(SCOPE, RULE));
	}

	expect(results.map((result) => result.ok)).toEqual([true, true, true, false]);
	expect(results[2]?.ok && results[2].value).toEqual({
		used: 3,
		remaining: 0,
		resetsAtMilliseconds: 3_000,
	});
	expect(!results[3]?.ok && results[3]?.error).toEqual({
		code: "rate-limited",
		resetsAtMilliseconds: 2_334,
	});

	vi.setSystemTime(2_333);

	expect((await meter.consume(SCOPE, RULE)).ok).toBe(false);

	vi.setSystemTime(2_334);

	expect((await meter.consume(SCOPE, RULE)).ok).toBe(true);
});

test("a refused request counts nothing, however many are refused", async () => {
	const { meter } = createFixture();

	for (let request = 0; request < 3; request += 1) {
		await meter.consume(SCOPE, RULE);
	}

	for (let request = 0; request < 20; request += 1) {
		expect((await meter.consume(SCOPE, RULE)).ok).toBe(false);
	}

	vi.setSystemTime(2_334);

	expect((await meter.consume(SCOPE, RULE)).ok).toBe(true);
});

test("a full limit does not pass twice across the boundary of two intervals", async () => {
	const { meter } = createFixture();

	vi.setSystemTime(1_999);

	for (let request = 0; request < 3; request += 1) {
		expect((await meter.consume(SCOPE, RULE)).ok).toBe(true);
	}

	vi.setSystemTime(2_000);

	expect((await meter.consume(SCOPE, RULE)).ok).toBe(false);
});

test("the count fades out as the previous interval leaves the window", async () => {
	const { meter } = createFixture();

	for (let request = 0; request < 3; request += 1) {
		await meter.consume(SCOPE, RULE);
	}

	const passes = [];

	for (const time of [2_000, 2_400, 2_700, 3_000, 3_000]) {
		vi.setSystemTime(time);
		passes.push((await meter.consume(SCOPE, RULE)).ok);
	}

	expect(passes).toEqual([false, true, true, true, false]);
});

test("a cost is counted whole, and a cost that does not fit counts nothing", async () => {
	const { meter } = createFixture();

	expect((await meter.consume(SCOPE, RULE, 2)).ok).toBe(true);
	expect((await meter.consume(SCOPE, RULE, 2)).ok).toBe(false);
	expect((await meter.consume(SCOPE, RULE, 1)).ok).toBe(true);
	expect((await meter.consume(SCOPE, RULE, 1)).ok).toBe(false);
});

test("counters of different tenants, resources and actors never mix", async () => {
	const { meter } = createFixture();
	const rule = meterRuleOf({ limit: 1, windowMilliseconds: 1_000 });

	await meter.consume(SCOPE, rule);

	for (const other of [
		{ ...SCOPE, tenant: "globex" },
		{ ...SCOPE, resource: "password" },
		{ ...SCOPE, actor: "bob" },
		{ tenant: "a", actor: "b:c", resource: "d" },
		{ tenant: "a}:meter:d:b", actor: "c", resource: "d" },
	]) {
		expect((await meter.consume(other, rule)).ok, JSON.stringify(other)).toBe(
			true,
		);
	}

	expect((await meter.consume(SCOPE, rule)).ok).toBe(false);
});

test("parallel requests are counted exactly once each", async () => {
	const { meter } = createFixture();
	const rule = meterRuleOf({ limit: 10, windowMilliseconds: 1_000 });

	const results = await Promise.all(
		Array.from({ length: 50 }, () => meter.consume(SCOPE, rule)),
	);

	expect(results.filter((result) => result.ok)).toHaveLength(10);
});

test("A26: a rule the meter cannot count is refused where it is defined, never when a request comes", async () => {
	for (const input of [
		{ limit: 0, windowMilliseconds: 1_000 },
		{ limit: 1.5, windowMilliseconds: 1_000 },
		{ limit: 1, windowMilliseconds: 1.5 },
		{ limit: Number.NaN, windowMilliseconds: 1_000 },
		{ limit: 1, windowMilliseconds: 0 },
		{ limit: 1, windowMilliseconds: Number.POSITIVE_INFINITY },
		{ limit: Number.MAX_SAFE_INTEGER + 1, windowMilliseconds: 1_000 },
	]) {
		expect(defineMeterRule(input), JSON.stringify(input)).toEqual({
			ok: false,
			error: "invalid-request",
		});
	}
});

test("A26: a cost the meter cannot count, or a look-alike rule, is a refusal that counts nothing", async () => {
	const { meter } = createFixture();
	const refused = { ok: false, error: { code: "invalid-request" } };

	for (const cost of [0, -1, 1.5, Number.NaN, 4]) {
		expect(await meter.consume(SCOPE, RULE, cost), String(cost)).toEqual(
			refused,
		);
	}

	const lookAlike = { limit: 1, windowMilliseconds: 1_000 };

	// @ts-expect-error a look-alike that did not come from defineMeterRule
	expect(await meter.consume(SCOPE, lookAlike)).toEqual(refused);

	expect(await meter.consume(SCOPE, RULE)).toMatchObject({
		ok: true,
		value: { used: 1 },
	});
});

test("a refusal is recorded, a request within the limit is not", async () => {
	const { meter, records } = createFixture();

	for (let request = 0; request < 4; request += 1) {
		await meter.consume(SCOPE, RULE);
	}

	expect(records).toHaveLength(1);
	expect(records[0]).toMatchObject({
		event: "meter.consume",
		outcome: "refusal",
		reason: "limit-exceeded",
		tenant: "acme",
		subject: "alice",
		detail: { resource: "email-link", limit: "3", used: "3" },
	});
});

test("a failing audit still refuses, and tells the caller", async () => {
	const { meter } = createFixture(async () => {
		throw new Error("the audit store is down");
	});

	for (let request = 0; request < 3; request += 1) {
		await meter.consume(SCOPE, RULE);
	}

	await expect(meter.consume(SCOPE, RULE)).rejects.toThrow(
		"the audit store is down",
	);
});

test("a failing store fails the call, it never lets the request through", async () => {
	const store: MeterStore = {
		consume: async () => {
			throw new Error("the counter store is down");
		},
	};
	const meter = createMeter({ store });

	await expect(meter.consume(SCOPE, RULE)).rejects.toThrow(
		"the counter store is down",
	);
});

test("a store that is full refuses new keys and keeps counting the old ones", async () => {
	const store = createMemoryMeterStore({ maximumBytes: 700 });
	const meter = createMeter({ store });
	const rule = meterRuleOf({ limit: 2, windowMilliseconds: 1_000 });
	const scopes = ["a", "b", "c"].map((actor) => ({ ...SCOPE, actor }));
	const first = [];

	for (const scope of scopes) {
		first.push((await meter.consume(scope, rule)).ok);
	}

	expect(first).toEqual([true, true, false]);
	expect((await meter.consume(scopes[0] ?? SCOPE, rule)).ok).toBe(true);
	expect((await meter.consume(scopes[0] ?? SCOPE, rule)).ok).toBe(false);

	vi.setSystemTime(3_000);

	expect((await meter.consume(scopes[2] ?? SCOPE, rule)).ok).toBe(true);
});

test("the memory meter store refuses a budget that is not a positive integer", () => {
	for (const maximumBytes of [0, -1, 1.5, Number.NaN]) {
		expect(() => createMemoryMeterStore({ maximumBytes })).toThrow(RangeError);
	}
});
