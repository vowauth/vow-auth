import { randomBytes } from "node:crypto";
import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type AuthOptions,
	type EpochStore,
	type Factor,
	fail,
	type IdentityStore,
	type MeterStore,
	succeed,
	type TokenRecord,
	type TokenStore,
} from "@vow-auth/core";
import type { DoctorTarget } from "@vow-auth/doctor";

export const goodOptions = (): AuthOptions => ({
	identities: createMemoryIdentityStore(),
	epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
	tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
	meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	secrets: [{ version: 1, value: randomBytes(32).toString("base64") }],
	maximumLifeTimeMilliseconds: 3_600_000,
	sessionTimeToLiveMilliseconds: 3_600_000,
	policy: () => "deny",
	audit: async () => undefined,
});

export const strictFactor: Factor = {
	id: "strict",
	strength: "possession",
	verify: async (response) => {
		const code =
			typeof response === "object" && response !== null
				? Reflect.get(response, "code")
				: undefined;

		return code === "424242"
			? succeed({
					provider: "strict",
					externalId: "alice",
					emailVerified: false,
				})
			: fail("invalid-proof");
	},
};

export const passthroughFactor: Factor = {
	id: "passthrough",
	strength: "possession",
	verify: async (response) => succeed(response),
};

export const goodTarget = (): DoctorTarget => ({
	options: goodOptions(),
	factors: [strictFactor],
});

export const nonAtomicTokenStore = (): TokenStore => {
	const records = new Map<string, TokenRecord>();

	return {
		put: async (hash, record) => {
			records.set(hash, record);
		},
		take: async (hash) => {
			const record = records.get(hash);

			await Promise.resolve();
			records.delete(hash);

			return record;
		},
	};
};

export const forgetfulTokenStore = (): TokenStore => ({
	put: async () => undefined,
	take: async () => undefined,
});

export const stuckEpochStore = (): EpochStore => ({
	read: async (keys) => ({ now: Date.now(), stamps: keys.map(() => 1) }),
	revoke: async () => 1,
});

export const unlimitedMeterStore = (): MeterStore => ({
	consume: async () => ({
		allowed: true,
		used: 0,
		remaining: 1,
		resetsAtMilliseconds: Date.now(),
	}),
});

export const splitBrainIdentityStore = (): IdentityStore => {
	const real = createMemoryIdentityStore();

	return {
		...real,
		createSubject: async () => ({
			subjectId: crypto.randomUUID(),
			isNew: true,
		}),
	};
};

export const tenantBlindIdentityStore = (): IdentityStore => {
	const real = createMemoryIdentityStore();
	const tenants = new Set<string>();

	return {
		...real,
		createSubject: async (tenant, identity) => {
			tenants.add(tenant);

			return real.createSubject(tenant, identity);
		},
		findSubject: async (_tenant, provider, externalId) => {
			for (const tenant of tenants) {
				const found = await real.findSubject(tenant, provider, externalId);

				if (found !== undefined) {
					return found;
				}
			}

			return undefined;
		},
	};
};
