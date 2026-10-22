import type { EpochStore } from "@vow-auth/core";
import { describe, expect, test } from "vitest";
import type { StoreClock } from "./store-clock.js";

/** What an adapter gives the epoch contract. */
export type EpochStoreContractOptions = {
	readonly create: () => EpochStore | Promise<EpochStore>;
	readonly clock: StoreClock;
	/**
	 * Returns a store with a tiny budget. Leave it out for an adapter that
	 * cannot be filled in a test. The contract then checks the one thing that
	 * must hold even when a store is full: a revocation is never undone.
	 */
	readonly full?: () => EpochStore | Promise<EpochStore>;
};

const HOUR = 3_600_000;

const uniqueKey = (name: string): string => {
	return `{contract-${crypto.randomUUID()}}:${name}:${crypto.randomUUID()}`;
};

/**
 * Defines the tests every `EpochStore` must pass: the store's own clock, one
 * stamp per key in order, strictly rising stamps for a key, a revocation that
 * lifts a key above every token issued before it, and expiry on the store's
 * clock. Call it inside a test file once per adapter.
 */
export function epochStoreContract(
	name: string,
	options: EpochStoreContractOptions,
): void {
	const { clock } = options;

	describe(`${name}: the epoch store contract`, () => {
		test("a read answers the store's time and one finite stamp per key in order", async () => {
			const store = await options.create();
			const first = uniqueKey("user");
			const second = uniqueKey("device");

			await store.revoke(second, HOUR);

			const reading = await store.read([first, second, uniqueKey("session")]);

			expect(Number.isFinite(reading.now)).toBe(true);
			expect(reading.stamps).toHaveLength(3);
			expect(reading.stamps.every(Number.isFinite)).toBe(true);
			expect(reading.stamps[0]).toBeLessThanOrEqual(reading.now);
			expect(reading.stamps[1]).toBeGreaterThan(reading.stamps[0] ?? 0);
			expect(await store.read([])).toEqual({
				now: expect.any(Number),
				stamps: [],
			});
		});

		test("a revocation lifts the key above what a token issued before it holds", async () => {
			const store = await options.create();
			const key = uniqueKey("user");
			const [before] = (await store.read([key])).stamps;
			const stamp = await store.revoke(key, HOUR);
			const [after] = (await store.read([key])).stamps;

			expect(stamp).toBeGreaterThan(before ?? 0);
			expect(after).toBeGreaterThanOrEqual(stamp);
		});

		test("a revocation is stamped no earlier than the store's own time", async () => {
			const store = await options.create();
			const now = (await store.read([])).now;

			expect(
				await store.revoke(uniqueKey("user"), HOUR),
			).toBeGreaterThanOrEqual(now);
		});

		test("stamps of one key rise strictly, in a row and in parallel", async () => {
			const store = await options.create();
			const key = uniqueKey("user");
			const stamps = [];

			for (let revocation = 0; revocation < 10; revocation += 1) {
				stamps.push(await store.revoke(key, HOUR));
			}

			const parallel = await Promise.all(
				Array.from({ length: 20 }, () => store.revoke(key, HOUR)),
			);

			expect(stamps).toEqual([...stamps].sort((a, b) => a - b));
			expect(new Set([...stamps, ...parallel]).size).toBe(30);
			expect((await store.read([key])).stamps[0]).toBe(
				Math.max(...stamps, ...parallel),
			);
		});

		test("revoking one key leaves another key alone", async () => {
			const store = await options.create();
			const revoked = uniqueKey("user");
			const other = uniqueKey("user");
			const [before] = (await store.read([other])).stamps;

			await store.revoke(revoked, HOUR);

			expect((await store.read([other])).stamps[0]).toBe(before);
		});

		test("a revocation expires on the store's clock and the key reads lower again", async () => {
			const store = await options.create();
			const key = uniqueKey("session");
			const stamp = await store.revoke(key, 300);

			await clock.advance(450);

			expect((await store.read([key])).stamps[0]).toBeLessThan(stamp);
		});

		test("a time to live that is not a positive finite number is refused", async () => {
			const store = await options.create();

			for (const timeToLive of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
				await expect(
					store.revoke(uniqueKey("user"), timeToLive),
				).rejects.toThrow();
			}
		});

		test.runIf(options.full !== undefined)(
			"a full store never undoes a revocation",
			async () => {
				const store = (await options.full?.()) ?? (await options.create());
				const revoked: { key: string; stamp: number }[] = [];

				for (let index = 0; index < 80; index += 1) {
					const key = uniqueKey("user");

					revoked.push({ key, stamp: await store.revoke(key, HOUR) });
				}

				const reading = await store.read(revoked.map(({ key }) => key));

				revoked.forEach(({ stamp }, index) => {
					expect(reading.stamps[index]).toBeGreaterThanOrEqual(stamp);
				});
			},
		);
	});
}
