import { createMemoryMeterStore } from "@vow-auth/adapter-memory";
import { applyLimit, assertLimit, type Limit, NO_LIMIT } from "@vow-auth/core";
import { createLimiter, createMeter } from "@vow-auth/core/internal";
import { meterRuleOf } from "@vow-auth/test-support";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

type Attempt = { readonly address: string; readonly target: string };

const createFixture = () => {
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});
	const limiter = createLimiter<Attempt>({
		meter,
		rule: meterRuleOf({ limit: 2, windowMilliseconds: 60_000 }),
		scopes: ({ address, target }) => [
			{ tenant: "acme", actor: address, resource: "sign-in:address" },
			{ tenant: "acme", actor: target, resource: "sign-in:target" },
		],
	});

	return { limiter, meter };
};

test("an attempt passes while every scope is within its limit", async () => {
	const { limiter } = createFixture();
	const attempt = { address: "1.1.1.1", target: "a@example.com" };

	expect(await limiter(attempt)).toEqual({ ok: true, value: undefined });
	expect(await limiter(attempt)).toEqual({ ok: true, value: undefined });
});

test("the first scope over its limit refuses, and says when to try again", async () => {
	const { limiter } = createFixture();
	const attempt = { address: "1.1.1.1", target: "a@example.com" };

	await limiter(attempt);
	await limiter(attempt);

	expect(await limiter(attempt)).toEqual({
		ok: false,
		error: {
			code: "rate-limited",
			resetsAtMilliseconds: expect.any(Number),
		},
	});
});

test("one address cannot use up the room of another, but many addresses cannot flood one target", async () => {
	const { limiter } = createFixture();
	const target = "victim@example.com";

	for (const [index, address] of ["1.1.1.1", "2.2.2.2"].entries()) {
		expect((await limiter({ address, target })).ok, String(index)).toBe(true);
	}

	expect(await limiter({ address: "3.3.3.3", target })).toMatchObject({
		ok: false,
		error: { code: "rate-limited" },
	});
	expect(
		(await limiter({ address: "3.3.3.3", target: "other@example.com" })).ok,
	).toBe(true);
});

test("each scope is counted on its own, so a refusal by one does not skip counting the others before it", async () => {
	const { limiter } = createFixture();

	await limiter({ address: "1.1.1.1", target: "a@example.com" });
	await limiter({ address: "1.1.1.1", target: "b@example.com" });

	expect(
		await limiter({ address: "1.1.1.1", target: "c@example.com" }),
	).toMatchObject({
		ok: false,
	});
});

test("a meter that cannot count refuses, never lets the attempt pass", async () => {
	const limiter = createLimiter<Attempt>({
		meter: {
			consume: async () => ({ ok: false, error: { code: "unavailable" } }),
		},
		rule: meterRuleOf({ limit: 1, windowMilliseconds: 1_000 }),
		scopes: () => [{ tenant: "acme", actor: "x", resource: "y" }],
	});

	expect(await limiter({ address: "a", target: "b" })).toEqual({
		ok: false,
		error: { code: "unavailable" },
	});
});

test("the choice of no limit is written as off, and anything else that is not a limiter is refused", async () => {
	const { limiter } = createFixture();
	const attempt = { address: "1.1.1.1", target: "a@example.com" };

	expect(NO_LIMIT).toBe("off");

	for (let count = 0; count < 5; count += 1) {
		expect(await applyLimit<Attempt>(NO_LIMIT, attempt)).toEqual({
			ok: true,
			value: undefined,
		});
	}

	expect(await applyLimit(limiter, attempt)).toEqual({
		ok: true,
		value: undefined,
	});

	for (const forgotten of [undefined, null, "", "on", 5, {}]) {
		// @ts-expect-error a value that is not a Limit
		const result = await applyLimit<Attempt>(forgotten, attempt);

		expect(result, String(forgotten)).toEqual({
			ok: false,
			error: { code: "invalid-request" },
		});
	}
});

test("a forgotten limit stops the start with a message that names the option", () => {
	const fine: Limit<Attempt>[] = [NO_LIMIT, createFixture().limiter];

	for (const limit of fine) {
		expect(() => assertLimit("limit", limit)).not.toThrow();
	}

	for (const forgotten of [undefined, null, "on", 0, {}]) {
		expect(() => assertLimit("signInLimit", forgotten)).toThrow(
			/signInLimit must be a limiter, or "off"/,
		);
	}
});
