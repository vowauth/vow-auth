import { createMemoryAccountStore } from "@vow-auth/adapter-memory";
import {
	type AccountStore,
	createRecordSeal,
	createRecords,
	type Records,
	type SecretVersion,
} from "@vow-auth/core/internal";

/** The secret the flow tests seal with. */
const FLOW_SECRETS: readonly SecretVersion[] = [
	{ version: 1, value: "flow-secret-0123456789abcdefghijklmn" },
];

/**
 * An account store in memory with the given tenants already created, and
 * the records that seal for it, as `createAuth` would build them.
 */
export const createAccounts = async (
	tenants: readonly string[] = ["acme"],
	secrets: readonly SecretVersion[] = FLOW_SECRETS,
): Promise<{ readonly store: AccountStore; readonly records: Records }> => {
	const store = createMemoryAccountStore();
	const records = createRecords(createRecordSeal({ secrets }));

	for (const id of tenants) {
		await store.createTenant(await records.tenant({ id, disabled: false }));
	}

	return { store, records };
};

/**
 * An account store in memory whose tenants are created before the first call
 * reaches it, for a fixture that cannot wait. The secrets must be the ones
 * of the engine that uses it.
 */
export const accountsWith = (
	tenants: readonly string[],
	secrets: readonly SecretVersion[],
): AccountStore => {
	const ready = createAccounts(tenants, secrets);
	const waiting: Record<string, unknown> = {};
	const methods = Object.keys(
		createMemoryAccountStore(),
	) as (keyof AccountStore)[];

	for (const name of methods) {
		waiting[name] = async (...input: unknown[]) => {
			const { store } = await ready;
			const method = store[name] as (...input: unknown[]) => Promise<unknown>;

			return method(...input);
		};
	}

	return waiting as AccountStore;
};
