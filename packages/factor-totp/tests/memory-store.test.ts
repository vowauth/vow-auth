import { isStoreFullError } from "@vow-auth/core";
import { createMemoryTotpStore, type TotpRecord } from "@vow-auth/factor-totp";
import { expect, test } from "vitest";

const record = (overrides: Partial<TotpRecord> = {}): TotpRecord => ({
	sealedSecret: "sealed",
	confirmed: true,
	lastStep: -1,
	backupCodeHashes: ["one", "two"],
	...overrides,
});

test("of many tries at one step, exactly one is accepted", async () => {
	const store = createMemoryTotpStore({ maximumRecords: 10 });

	await store.save("acc_alice", record());

	const results = await Promise.all(
		Array.from({ length: 50 }, () => store.advance("acc_alice", 7)),
	);

	expect(results.filter(Boolean)).toHaveLength(1);
	expect(await store.advance("acc_alice", 7)).toBe(false);
	expect(await store.advance("acc_alice", 6)).toBe(false);
	expect(await store.advance("acc_alice", 8)).toBe(true);
	expect((await store.find("acc_alice"))?.lastStep).toBe(8);
});

test("of many tries with one backup code, exactly one is accepted", async () => {
	const store = createMemoryTotpStore({ maximumRecords: 10 });

	await store.save("acc_alice", record());

	const results = await Promise.all(
		Array.from({ length: 50 }, () => store.spendBackupCode("acc_alice", "one")),
	);

	expect(results.filter(Boolean)).toHaveLength(1);
	expect((await store.find("acc_alice"))?.backupCodeHashes).toEqual(["two"]);
});

test("nothing is advanced or spent for an account that has no record", async () => {
	const store = createMemoryTotpStore({ maximumRecords: 10 });

	expect(await store.advance("acc_nobody", 1)).toBe(false);
	expect(await store.spendBackupCode("acc_nobody", "one")).toBe(false);
	expect(await store.remove("acc_nobody")).toBe(false);
});

test("accounts are kept apart, whatever characters they hold", async () => {
	const store = createMemoryTotpStore({ maximumRecords: 10 });

	await store.save("a,b", record({ sealedSecret: "first" }));
	await store.save("a", record({ sealedSecret: "second" }));

	expect((await store.find("a,b"))?.sealedSecret).toBe("first");
	expect((await store.find("a"))?.sealedSecret).toBe("second");
});

test("a record that is read cannot be changed through the copy", async () => {
	const store = createMemoryTotpStore({ maximumRecords: 10 });

	await store.save("acc_alice", record());

	const copy = await store.find("acc_alice");

	if (copy !== undefined) {
		Array.prototype.push.call(copy.backupCodeHashes, "forged");
	}

	expect((await store.find("acc_alice"))?.backupCodeHashes).toEqual([
		"one",
		"two",
	]);
});

test("a full store refuses a new account and never drops a live one", async () => {
	const store = createMemoryTotpStore({ maximumRecords: 2 });

	await store.save("acc_a", record());
	await store.save("acc_b", record());

	await expect(store.save("acc_c", record())).rejects.toSatisfy(
		isStoreFullError,
	);
	await store.save("acc_a", record({ lastStep: 3 }));

	expect((await store.find("acc_a"))?.lastStep).toBe(3);
	expect(await store.find("acc_b")).toBeDefined();

	await store.remove("acc_b");
	await store.save("acc_c", record());

	expect(await store.find("acc_c")).toBeDefined();
});

test("the size of the store must be a positive integer", () => {
	for (const maximumRecords of [0, -1, 1.5, Number.NaN]) {
		expect(() => createMemoryTotpStore({ maximumRecords })).toThrow(RangeError);
	}
});
