import {
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

test("D4: expired entries leave the numbers, live ones stay", async () => {
	const meter = createMemoryMeterStore({ maximumBytes: 1_000_000 });
	const tokens = createMemoryTokenStore({ maximumBytes: 1_000_000 });

	await meter.consume({
		key: "{a}:meter:r:1",
		cost: 1,
		limit: 5,
		windowMilliseconds: 1_000,
	});
	await tokens.put("hash", {
		purpose: "p",
		payload: {},
		expiresAtMilliseconds: Date.now() + 500,
	});

	expect(meter.stats().entries).toBe(1);
	expect(tokens.stats().entries).toBe(1);

	vi.setSystemTime(Date.now() + 5_000);
	await meter.consume({
		key: "{a}:meter:r:2",
		cost: 1,
		limit: 5,
		windowMilliseconds: 1_000,
	});
	await tokens.take("nothing");

	expect(meter.stats().entries).toBe(1);
	expect(tokens.stats().entries).toBe(0);
	expect(tokens.stats().usedBytes).toBe(0);
});
