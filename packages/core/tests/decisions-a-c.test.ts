import {
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AuditRecord,
	type AuditSink,
	isStoreFullError,
} from "@vow-auth/core";
import { createMeter, createTokens } from "@vow-auth/core/internal";
import { durationOf, meterRuleOf } from "@vow-auth/store-contracts";
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

const unwrap = <Value>(
	result: { readonly ok: true; readonly value: Value } | { readonly ok: false },
): Value => {
	if (!result.ok) {
		throw new Error("the meter must accept this rule");
	}

	return result.value;
};

const collect = () => {
	const records: AuditRecord[] = [];
	const sink: AuditSink = async (record) => {
		records.push(record);
	};

	return { records, sink };
};

test("C4: observe never refuses and records only what enforcement would have refused", async () => {
	const { records, sink } = collect();
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		audit: sink,
	});
	const seen = [];

	for (let request = 0; request < 5; request += 1) {
		seen.push(unwrap(await meter.observe(SCOPE, RULE)));
	}

	expect(seen.map((observation) => observation.wouldRefuse)).toEqual([
		false,
		false,
		false,
		true,
		true,
	]);
	expect(seen[3]?.resetsAtMilliseconds).toBeGreaterThan(Date.now());
	expect(
		records.map((record) => [record.event, record.outcome, record.reason]),
	).toEqual([
		["meter.consume", "observation", "limit-exceeded"],
		["meter.consume", "observation", "limit-exceeded"],
	]);
});

test("C4: what observe sees is exactly what consume would enforce on the same traffic", async () => {
	const observed = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});
	const enforced = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});

	for (const step of [0, 0, 0, 0, 400, 300, 0, 600, 1_000, 0, 0]) {
		vi.setSystemTime(Date.now() + step);

		const watching = unwrap(await observed.observe(SCOPE, RULE));
		const enforcing = await enforced.consume(SCOPE, RULE);

		expect(watching.wouldRefuse).toBe(!enforcing.ok);
	}
});

test("C4: observe still refuses nothing when the store is full, and says why", async () => {
	const { records, sink } = collect();
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 700 }),
		audit: sink,
	});

	for (const actor of ["a", "b", "c"]) {
		await meter.observe({ ...SCOPE, actor }, RULE);
	}

	expect(records.map((record) => [record.outcome, record.reason])).toEqual([
		["observation", "capacity"],
	]);
});

test("D4: a request refused because the store is full is told apart from one over the limit", async () => {
	const { records, sink } = collect();
	const store = createMemoryMeterStore({ maximumBytes: 700 });
	const meter = createMeter({ store, audit: sink });
	const results = [];

	for (const actor of ["a", "b", "c"]) {
		results.push(await meter.consume({ ...SCOPE, actor }, RULE));
	}

	for (let request = 0; request < 3; request += 1) {
		await meter.consume({ ...SCOPE, actor: "a" }, RULE);
	}

	expect(results.map((result) => result.ok)).toEqual([true, true, false]);
	expect(records.map((record) => record.reason)).toEqual([
		"capacity",
		"limit-exceeded",
	]);
	expect(store.stats()).toMatchObject({ capacityRefusals: 1, evictions: 0 });
});

test("A2: a full token store refuses a new token and keeps every pending one", async () => {
	const { records, sink } = collect();
	const store = createMemoryTokenStore({ maximumBytes: 1_500 });
	const tokens = createTokens({ store, audit: sink });
	const issued: string[] = [];
	let failure: unknown;

	for (let request = 0; request < 20 && failure === undefined; request += 1) {
		try {
			issued.push(
				await tokens.issue({
					purpose: "email-link",
					timeToLive: durationOf(60_000),
				}),
			);
		} catch (error) {
			failure = error;
		}
	}

	expect(isStoreFullError(failure)).toBe(true);
	expect(issued.length).toBeGreaterThan(0);

	for (const token of issued) {
		expect((await tokens.consume(token, "email-link")).ok).toBe(true);
	}

	expect(
		records.filter((record) => record.event === "token.issue").at(-1),
	).toMatchObject({ outcome: "refusal", reason: "capacity" });
	expect(
		records.filter(
			(record) =>
				record.event === "token.issue" && record.outcome === "success",
		),
	).toHaveLength(issued.length);
	expect(store.stats().capacityRefusals).toBe(1);
});

test("A2: a token the store could not keep is never handed out", async () => {
	const tokens = createTokens({
		store: {
			put: async () => {
				throw new Error("the token store is down");
			},
			take: async () => undefined,
		},
	});

	await expect(
		tokens.issue({ purpose: "email-link", timeToLive: durationOf(1_000) }),
	).rejects.toThrow("the token store is down");
});
