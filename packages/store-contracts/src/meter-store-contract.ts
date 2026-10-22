import type { MeterStore } from "@vow-auth/core";
import { describe, expect, test } from "vitest";
import type { StoreClock } from "./store-clock.js";

/** What an adapter gives the meter contract. */
export type MeterStoreContractOptions = {
	/** Returns a store; the contract uses its own unique keys, so one store may serve every test. */
	readonly create: () => MeterStore | Promise<MeterStore>;
	readonly clock: StoreClock;
	/**
	 * Returns a store with a tiny budget. Leave it out for an adapter that
	 * cannot be filled in a test. The contract then checks that a full store
	 * never answers `allowed` for more keys than it can hold and that the keys
	 * it admitted keep their limits.
	 */
	readonly full?: () => MeterStore | Promise<MeterStore>;
};

const MINUTE = 60_000;

const uniqueKey = (name: string): string => {
	return `{contract-${crypto.randomUUID()}}:meter:${name}`;
};

/**
 * Defines the tests every `MeterStore` must pass, so that adapters cannot
 * drift apart: the sliding window of Cloudflare's rate limiting, atomic
 * counting, refused requests that count nothing, and a retry moment that is
 * told truthfully. Call it inside a test file once per adapter.
 */
export function meterStoreContract(
	name: string,
	options: MeterStoreContractOptions,
): void {
	const { clock } = options;

	describe(`${name}: the meter store contract`, () => {
		test("requests pass up to the limit and report what is used", async () => {
			const store = await options.create();
			const key = uniqueKey("limit");
			const results = [];

			for (let request = 0; request < 4; request += 1) {
				results.push(
					await store.consume({
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
			expect(results.map((result) => result.remaining)).toEqual([2, 1, 0, 0]);
			expect(results[3]?.resetsAtMilliseconds).toBeGreaterThan(
				await clock.now(),
			);
		});

		test("a refused request counts nothing, however many are refused", async () => {
			const store = await options.create();
			const key = uniqueKey("refusal");
			const consume = () =>
				store.consume({ key, cost: 1, limit: 1, windowMilliseconds: MINUTE });

			await consume();

			for (let request = 0; request < 8; request += 1) {
				expect((await consume()).used).toBe(1);
			}
		});

		test("a cost is counted whole, and a cost that does not fit counts nothing", async () => {
			const store = await options.create();
			const key = uniqueKey("cost");
			const consume = (cost: number) =>
				store.consume({ key, cost, limit: 3, windowMilliseconds: MINUTE });

			expect((await consume(2)).allowed).toBe(true);
			expect((await consume(2)).allowed).toBe(false);
			expect((await consume(1)).allowed).toBe(true);
			expect((await consume(1)).allowed).toBe(false);
		});

		test("parallel requests are counted exactly once each", async () => {
			const store = await options.create();
			const key = uniqueKey("burst");
			const results = await Promise.all(
				Array.from({ length: 50 }, () =>
					store.consume({
						key,
						cost: 1,
						limit: 10,
						windowMilliseconds: MINUTE,
					}),
				),
			);

			expect(results.filter((result) => result.allowed)).toHaveLength(10);
		});

		test("keys never share a counter", async () => {
			const store = await options.create();
			const first = uniqueKey("first");
			const second = uniqueKey("second");
			const consume = (key: string) =>
				store.consume({ key, cost: 1, limit: 1, windowMilliseconds: MINUTE });

			expect((await consume(first)).allowed).toBe(true);
			expect((await consume(first)).allowed).toBe(false);
			expect((await consume(second)).allowed).toBe(true);
		});

		test("a refused request passes at the moment it was told", async () => {
			const store = await options.create();
			const key = uniqueKey("told");
			const consume = () =>
				store.consume({ key, cost: 1, limit: 1, windowMilliseconds: 400 });

			await consume();

			const refused = await consume();

			expect(refused.allowed).toBe(false);

			await clock.advance(
				Math.max(0, refused.resetsAtMilliseconds - (await clock.now())) + 40,
			);

			expect((await consume()).allowed).toBe(true);
		});

		test("a key used with another window length starts again", async () => {
			const store = await options.create();
			const key = uniqueKey("rule-change");

			await store.consume({
				key,
				cost: 1,
				limit: 1,
				windowMilliseconds: MINUTE,
			});

			expect(
				(
					await store.consume({
						key,
						cost: 1,
						limit: 1,
						windowMilliseconds: 2 * MINUTE,
					})
				).allowed,
			).toBe(true);
		});

		test.runIf(clock.set !== undefined)(
			"a full limit does not pass twice across the boundary of two intervals",
			async () => {
				const store = await options.create();
				const key = uniqueKey("boundary");
				const consume = () =>
					store.consume({ key, cost: 1, limit: 3, windowMilliseconds: 1_000 });
				const base = Math.floor((await clock.now()) / 1_000) * 1_000 + 10_000;

				clock.set?.(base + 999);

				for (let request = 0; request < 3; request += 1) {
					expect((await consume()).allowed).toBe(true);
				}

				clock.set?.(base + 1_000);

				expect((await consume()).allowed).toBe(false);
			},
		);

		test.runIf(options.full !== undefined)(
			"a full store never allows more than it can hold, and the keys it admitted keep their limits",
			async () => {
				const store = (await options.full?.()) ?? (await options.create());
				const keys = Array.from({ length: 60 }, (_, index) =>
					uniqueKey(`flood-${index}`),
				);
				const outcomes: boolean[] = [];

				for (const key of keys) {
					try {
						outcomes.push(
							(
								await store.consume({
									key,
									cost: 1,
									limit: 1,
									windowMilliseconds: MINUTE,
								})
							).allowed,
						);
					} catch {
						outcomes.push(false);
					}
				}

				const admitted = keys.filter((_, index) => outcomes[index]);

				expect(admitted.length).toBeGreaterThan(0);
				expect(admitted.length).toBeLessThan(keys.length);

				for (const key of admitted) {
					expect(
						(
							await store.consume({
								key,
								cost: 1,
								limit: 1,
								windowMilliseconds: MINUTE,
							})
						).allowed,
					).toBe(false);
				}
			},
		);
	});
}
