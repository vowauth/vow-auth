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
import { durationOf, meterRuleOf } from "@vow-auth/test-support";
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

const collect = () => {
	const records: AuditRecord[] = [];
	const sink: AuditSink = async (record) => {
		records.push(record);
	};

	return { records, sink };
};

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
