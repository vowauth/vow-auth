import type { OutboxStore } from "@vow-auth/core";
import { describe, expect, test } from "vitest";
import type { StoreClock } from "./store-clock.js";

/** What an adapter gives the outbox contract. */
export type OutboxStoreContractOptions = {
	readonly create: () => OutboxStore | Promise<OutboxStore>;
	readonly clock: StoreClock;
};

const LEASE = 10_000;

const event = (name: string) => ({
	id: `${name}-${crypto.randomUUID()}`,
	type: "mail",
	payload: { to: "a@example.com" },
});

/**
 * Defines the tests every `OutboxStore` must pass: an event is delivered to
 * one worker at a time, a lease that runs out gives it to another, a stale
 * worker cannot undo a newer claim, and a buried or completed event never
 * comes back. Call it inside a test file once per adapter.
 */
export function outboxStoreContract(
	name: string,
	options: OutboxStoreContractOptions,
): void {
	const { clock } = options;

	describe(`${name}: the outbox store contract`, () => {
		test("a claim returns the event with its first attempt and the payload it was given", async () => {
			const store = await options.create();
			const appended = event("first");

			await store.append(appended);

			expect(
				await store.claim({ limit: 10, leaseMilliseconds: LEASE }),
			).toEqual([{ ...appended, attempts: 1 }]);
		});

		test("a claim takes no more than its limit and an empty outbox gives nothing", async () => {
			const store = await options.create();

			expect(await store.claim({ limit: 5, leaseMilliseconds: LEASE })).toEqual(
				[],
			);

			await Promise.all([1, 2, 3].map(() => store.append(event("many"))));

			expect(
				await store.claim({ limit: 2, leaseMilliseconds: LEASE }),
			).toHaveLength(2);
			expect(
				await store.claim({ limit: 2, leaseMilliseconds: LEASE }),
			).toHaveLength(1);
		});

		test("a claimed event is hidden for the lease and claimable again after it, with another attempt", async () => {
			const store = await options.create();

			await store.append(event("lease"));
			await store.claim({ limit: 1, leaseMilliseconds: LEASE });
			await clock.advance(LEASE / 2);

			expect(await store.claim({ limit: 1, leaseMilliseconds: LEASE })).toEqual(
				[],
			);

			await clock.advance(LEASE);

			const [again] = await store.claim({ limit: 1, leaseMilliseconds: LEASE });

			expect(again?.attempts).toBe(2);
		});

		test("two workers claiming at once never get the same event", async () => {
			const store = await options.create();

			await Promise.all(
				Array.from({ length: 6 }, () => store.append(event("race"))),
			);

			const claims = await Promise.all(
				Array.from({ length: 4 }, () =>
					store.claim({ limit: 3, leaseMilliseconds: LEASE }),
				),
			);
			const ids = claims.flat().map((record) => record.id);

			expect(ids).toHaveLength(6);
			expect(new Set(ids).size).toBe(6);
		});

		test("a completed event never comes back", async () => {
			const store = await options.create();

			await store.append(event("done"));

			const [record] = await store.claim({
				limit: 1,
				leaseMilliseconds: LEASE,
			});

			if (record === undefined) {
				throw new Error("the event must be claimed");
			}

			await store.complete(record);
			await clock.advance(LEASE * 2);

			expect(await store.claim({ limit: 1, leaseMilliseconds: LEASE })).toEqual(
				[],
			);
		});

		test("a released event waits for its delay and then comes back", async () => {
			const store = await options.create();

			await store.append(event("retry"));

			const [record] = await store.claim({
				limit: 1,
				leaseMilliseconds: LEASE,
			});

			if (record === undefined) {
				throw new Error("the event must be claimed");
			}

			await store.release(record, 5_000);
			await clock.advance(2_000);

			expect(await store.claim({ limit: 1, leaseMilliseconds: LEASE })).toEqual(
				[],
			);

			await clock.advance(5_000);

			const [again] = await store.claim({ limit: 1, leaseMilliseconds: LEASE });

			expect(again?.id).toBe(record.id);
			expect(again?.attempts).toBe(2);
		});

		test("a buried event never comes back", async () => {
			const store = await options.create();

			await store.append(event("buried"));

			const [record] = await store.claim({
				limit: 1,
				leaseMilliseconds: LEASE,
			});

			if (record === undefined) {
				throw new Error("the event must be claimed");
			}

			await store.bury(record);
			await clock.advance(LEASE * 2);

			expect(await store.claim({ limit: 1, leaseMilliseconds: LEASE })).toEqual(
				[],
			);
		});

		test("a worker whose lease ran out cannot complete, release or bury a newer claim", async () => {
			const store = await options.create();

			await store.append(event("stale"));

			const [stale] = await store.claim({ limit: 1, leaseMilliseconds: LEASE });

			if (stale === undefined) {
				throw new Error("the event must be claimed");
			}

			await clock.advance(LEASE * 2);

			const [fresh] = await store.claim({ limit: 1, leaseMilliseconds: LEASE });

			expect(fresh?.attempts).toBe(2);

			await store.complete(stale);
			await store.release(stale, 0);
			await store.bury(stale);

			expect(await store.claim({ limit: 1, leaseMilliseconds: LEASE })).toEqual(
				[],
			);

			if (fresh === undefined) {
				throw new Error("the event must be claimed again");
			}

			await store.release(fresh, 0);

			expect(
				(await store.claim({ limit: 1, leaseMilliseconds: LEASE }))[0]
					?.attempts,
			).toBe(3);
		});

		test("the store keeps its own copy of the payload", async () => {
			const store = await options.create();
			const payload = { to: "a@example.com" };

			await store.append({
				id: `copy-${crypto.randomUUID()}`,
				type: "mail",
				payload,
			});
			payload.to = "evil@example.com";

			const [record] = await store.claim({
				limit: 1,
				leaseMilliseconds: LEASE,
			});

			expect(record?.payload).toEqual({ to: "a@example.com" });
		});
	});
}
