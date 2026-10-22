import { type SlidingWindowState, slidingWindow } from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

const MINUTE = 60_000;

test("the example of Cloudflare: 42 requests last minute, 18 this minute, 15 seconds in, estimate 49.5", () => {
	const state: SlidingWindowState = {
		windowMilliseconds: MINUTE,
		index: 1,
		current: 18,
		previous: 42,
	};
	const now = MINUTE + 15_000;
	const refused = slidingWindow({
		state,
		nowMilliseconds: now,
		windowMilliseconds: MINUTE,
		limit: 50,
		cost: 1,
	});
	const allowed = slidingWindow({
		state,
		nowMilliseconds: now,
		windowMilliseconds: MINUTE,
		limit: 51,
		cost: 1,
	});

	expect(refused.allowed).toBe(false);
	expect(refused.estimate).toBeCloseTo(49.5, 9);
	expect(allowed.allowed).toBe(true);
	expect(allowed.estimate).toBeCloseTo(50.5, 9);
	expect(allowed.state).toEqual({ ...state, current: 19 });
});

test("a key never seen starts from zero, and a key two intervals old has forgotten everything", () => {
	const fresh = slidingWindow({
		state: undefined,
		nowMilliseconds: 5_500,
		windowMilliseconds: 1_000,
		limit: 2,
		cost: 2,
	});

	expect(fresh.allowed).toBe(true);
	expect(fresh.state).toEqual({
		windowMilliseconds: 1_000,
		index: 5,
		current: 2,
		previous: 0,
	});

	const old = slidingWindow({
		state: { windowMilliseconds: 1_000, index: 5, current: 2, previous: 2 },
		nowMilliseconds: 7_000,
		windowMilliseconds: 1_000,
		limit: 2,
		cost: 2,
	});

	expect(old.allowed).toBe(true);
	expect(old.state.previous).toBe(0);
});

test("a changed window length starts the key again", () => {
	const outcome = slidingWindow({
		state: { windowMilliseconds: 1_000, index: 5, current: 9, previous: 9 },
		nowMilliseconds: 5_500,
		windowMilliseconds: 2_000,
		limit: 2,
		cost: 1,
	});

	expect(outcome.allowed).toBe(true);
	expect(outcome.state).toEqual({
		windowMilliseconds: 2_000,
		index: 2,
		current: 1,
		previous: 0,
	});
});

test("a clock that moved back keeps the newer interval and reads it as just begun, the stricter reading", () => {
	const outcome = slidingWindow({
		state: { windowMilliseconds: 1_000, index: 9, current: 1, previous: 2 },
		nowMilliseconds: 4_500,
		windowMilliseconds: 1_000,
		limit: 3,
		cost: 1,
	});

	expect(outcome.state.index).toBe(9);
	expect(outcome.estimate).toBe(3);
	expect(outcome.allowed).toBe(false);
});

const stateArbitrary = fastCheck.record({
	index: fastCheck.integer({ min: 1, max: 50 }),
	current: fastCheck.integer({ min: 0, max: 20 }),
	previous: fastCheck.integer({ min: 0, max: 20 }),
});

test("the rate never falls below zero or rises as time passes without requests", () => {
	fastCheck.assert(
		fastCheck.property(
			stateArbitrary,
			fastCheck.integer({ min: 100, max: 5_000 }),
			fastCheck.integer({ min: 0, max: 20_000 }),
			fastCheck.integer({ min: 0, max: 20_000 }),
			(counters, windowMilliseconds, firstOffset, extra) => {
				const state = { windowMilliseconds, ...counters };
				const first = counters.index * windowMilliseconds + firstOffset;
				const estimateAt = (now: number) =>
					slidingWindow({
						state,
						nowMilliseconds: now,
						windowMilliseconds,
						limit: 1_000,
						cost: 1,
					}).estimate;

				expect(estimateAt(first + extra)).toBeLessThanOrEqual(
					estimateAt(first) + 1e-9,
				);
				expect(estimateAt(first)).toBeGreaterThanOrEqual(0);
			},
		),
		{ numRuns: 500 },
	);
});

test("a refused request is told the earliest moment it passes: refused just before, allowed at it", () => {
	fastCheck.assert(
		fastCheck.property(
			stateArbitrary,
			fastCheck.integer({ min: 200, max: 5_000 }),
			fastCheck.integer({ min: 0, max: 4_999 }),
			fastCheck.integer({ min: 1, max: 12 }),
			fastCheck.integer({ min: 1, max: 5 }),
			(counters, windowMilliseconds, offset, limit, cost) => {
				fastCheck.pre(cost <= limit);

				const state = { windowMilliseconds, ...counters };
				const now =
					counters.index * windowMilliseconds + (offset % windowMilliseconds);
				const decide = (time: number) =>
					slidingWindow({
						state,
						nowMilliseconds: time,
						windowMilliseconds,
						limit,
						cost,
					});
				const refused = decide(now);

				fastCheck.pre(!refused.allowed);

				const retryAt = refused.retryAtMilliseconds;

				expect(retryAt).toBeGreaterThan(now);
				expect(decide(retryAt).allowed).toBe(true);
				expect(decide(retryAt - 2).allowed).toBe(false);
			},
		),
		{ numRuns: 1_000 },
	);
});

test("whatever the sequence of requests, a counted request never takes the rate above the limit", () => {
	fastCheck.assert(
		fastCheck.property(
			fastCheck.array(
				fastCheck.record({
					step: fastCheck.integer({ min: 0, max: 700 }),
					cost: fastCheck.integer({ min: 1, max: 3 }),
				}),
				{ maxLength: 80 },
			),
			(requests) => {
				let state: SlidingWindowState | undefined;
				let now = 10_000;

				for (const request of requests) {
					now += request.step;

					const outcome = slidingWindow({
						state,
						nowMilliseconds: now,
						windowMilliseconds: 1_000,
						limit: 5,
						cost: request.cost,
					});

					if (outcome.allowed) {
						expect(outcome.estimate).toBeLessThanOrEqual(5 + 1e-9);
						state = outcome.state;
					}
				}
			},
		),
		{ numRuns: 300 },
	);
});
