import {
	createMemoryAccountStore,
	createMemoryEpochStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	accountStoreContract,
	epochStoreContract,
	meterStoreContract,
	type StoreClock,
	tokenStoreContract,
} from "@vow-auth/store-contracts";
import { afterEach, beforeEach, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const clock: StoreClock = {
	now: async () => Date.now(),
	advance: async (milliseconds) => {
		vi.setSystemTime(Date.now() + milliseconds);
	},
	set: (milliseconds) => {
		vi.setSystemTime(milliseconds);
	},
};

const BIG = 10_000_000;
const TINY = 700;

meterStoreContract("memory", {
	create: () => createMemoryMeterStore({ maximumBytes: BIG }),
	full: () => createMemoryMeterStore({ maximumBytes: TINY }),
	clock,
});

epochStoreContract("memory", {
	create: () => createMemoryEpochStore({ maximumBytes: BIG }),
	full: () => createMemoryEpochStore({ maximumBytes: TINY }),
	clock,
});

tokenStoreContract("memory", {
	create: () => createMemoryTokenStore({ maximumBytes: BIG }),
	full: () => ({
		store: createMemoryTokenStore({ maximumBytes: 2_000 }),
		policy: "refuse-new",
	}),
	clock,
});

accountStoreContract("memory", { create: () => createMemoryAccountStore() });
