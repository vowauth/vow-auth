import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { type Auth, createAuth, type Factor, succeed } from "@vow-auth/core";
import {
	type AuthHandler,
	createAuthClient,
	createAuthHandler,
	type ServiceSurface,
	type UnavailableReason,
} from "@vow-auth/service";

export const SERVICE_TOKEN = "service-secret-0123456789abcdefghijklmnop";
export const BASE_URL = "http://auth.test";

export type Mode = "in-process" | "remote";

export const claimsFactor: Factor = {
	id: "claims",
	strength: "possession",
	verify: async (response) => succeed(response),
};

export const createCore = () => {
	const banned = new Set<string>();
	const auth: Auth = createAuth({
		identities: createMemoryIdentityStore(),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: "service-seal-0123456789abcdefghijklmn" }],
		maximumLifeTimeMilliseconds: 3_600_000,
		sessionTimeToLiveMilliseconds: 3_600_000,
		policy: ({ subject }) => (banned.has(subject) ? "deny" : "allow"),
		audit: async () => undefined,
	});

	return { auth, banned };
};

export const createHandler = (auth: Auth): AuthHandler => {
	return createAuthHandler({
		auth,
		factors: { [claimsFactor.id]: claimsFactor },
		serviceTokens: [SERVICE_TOKEN],
		maximumBodyBytes: 10_000,
	});
};

export const createService = (mode: Mode) => {
	const { auth, banned } = createCore();
	const reasons: UnavailableReason[] = [];
	const surface: ServiceSurface =
		mode === "in-process"
			? auth
			: createAuthClient({
					baseUrl: BASE_URL,
					serviceToken: SERVICE_TOKEN,
					timeoutMilliseconds: 5_000,
					fetch: (input, init) => createHandler(auth)(new Request(input, init)),
					onUnavailable: (reason) => {
						reasons.push(reason);
					},
				});

	return { surface, banned, reasons };
};

export const verifiedClaims = (email: string, provider = "email") => ({
	provider,
	externalId: email,
	email,
	emailVerified: true,
});

export const unverifiedClaims = (
	provider: string,
	externalId: string,
	email: string,
) => ({ provider, externalId, email, emailVerified: false });
