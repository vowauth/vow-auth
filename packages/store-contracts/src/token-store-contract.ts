import type { TokenRecord, TokenStore } from "@vow-auth/core";
import { describe, expect, test } from "vitest";
import type { StoreClock } from "./store-clock.js";

/** What an adapter does when it has no room for one more record. */
export type TokenStoreOverflowPolicy = "evict-oldest" | "refuse-new";

/** What an adapter gives the token contract. */
export type TokenStoreContractOptions = {
	readonly create: () => TokenStore | Promise<TokenStore>;
	readonly clock: StoreClock;
	/**
	 * Returns a store with a tiny budget and the policy it follows when full.
	 * Leave it out for an adapter that cannot be filled in a test. The policy
	 * is declared, not tolerated: an adapter that changes it has to say so.
	 */
	readonly full?: () =>
		| { readonly store: TokenStore; readonly policy: TokenStoreOverflowPolicy }
		| Promise<{
				readonly store: TokenStore;
				readonly policy: TokenStoreOverflowPolicy;
		  }>;
};

const uniqueHash = (): string => {
	return `${crypto.randomUUID()}${crypto.randomUUID()}`.replaceAll("-", "");
};

const recordExpiring = async (
	clock: StoreClock,
	timeToLiveMilliseconds: number,
	payload: Readonly<Record<string, string>> = {},
): Promise<TokenRecord> => ({
	purpose: "email-link",
	payload,
	expiresAtMilliseconds: (await clock.now()) + timeToLiveMilliseconds,
});

/**
 * Defines the tests every `TokenStore` must pass: a record is taken at most
 * once even by parallel callers, the store keeps its own copy, and an expired
 * record is never redeemable. Call it inside a test file once per adapter.
 */
export function tokenStoreContract(
	name: string,
	options: TokenStoreContractOptions,
): void {
	const { clock } = options;

	describe(`${name}: the token store contract`, () => {
		test("a record is taken once, and an unknown hash gives nothing", async () => {
			const store = await options.create();
			const hash = uniqueHash();
			const record = await recordExpiring(clock, 60_000, { email: "a@b.c" });

			await store.put(hash, record);

			expect(await store.take(hash)).toEqual(record);
			expect(await store.take(hash)).toBeUndefined();
			expect(await store.take(uniqueHash())).toBeUndefined();
		});

		test("parallel takes give the record to exactly one caller", async () => {
			const store = await options.create();
			const hash = uniqueHash();

			await store.put(hash, await recordExpiring(clock, 60_000));

			const taken = await Promise.all(
				Array.from({ length: 20 }, () => store.take(hash)),
			);

			expect(taken.filter((record) => record !== undefined)).toHaveLength(1);
		});

		test("the store keeps its own copy of what it was given", async () => {
			const store = await options.create();
			const hash = uniqueHash();
			const payload = { email: "a@example.com" };

			await store.put(hash, await recordExpiring(clock, 60_000, payload));
			payload.email = "attacker@example.com";

			expect((await store.take(hash))?.payload).toEqual({
				email: "a@example.com",
			});
		});

		test("an expired record is never redeemable", async () => {
			const store = await options.create();
			const hash = uniqueHash();

			await store.put(hash, await recordExpiring(clock, 200));
			await clock.advance(350);

			const taken = await store.take(hash);

			expect(
				taken === undefined ||
					taken.expiresAtMilliseconds <= (await clock.now()),
			).toBe(true);
		});

		test.runIf(options.full !== undefined)(
			"a full store follows its declared policy and never invents a record",
			async () => {
				const full = await options.full?.();

				if (full === undefined) {
					return;
				}

				const hashes = Array.from({ length: 60 }, () => uniqueHash());
				const rejected: boolean[] = [];

				for (const hash of hashes) {
					try {
						await full.store.put(
							hash,
							await recordExpiring(clock, 60_000, { id: hash }),
						);
						rejected.push(false);
					} catch {
						rejected.push(true);
					}
				}

				const taken = [];

				for (const hash of hashes) {
					taken.push(await full.store.take(hash));
				}

				for (const [index, record] of taken.entries()) {
					expect(
						record === undefined || record.payload.id === hashes[index],
					).toBe(true);
				}

				if (full.policy === "refuse-new") {
					expect(rejected.some(Boolean)).toBe(true);
					expect(taken[0]).toBeDefined();
				} else {
					expect(rejected.some(Boolean)).toBe(false);
					expect(taken.at(-1)).toBeDefined();
					expect(taken.some((record) => record === undefined)).toBe(true);
				}
			},
		);
	});
}
