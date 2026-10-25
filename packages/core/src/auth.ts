import type { AccountStore } from "./accounts/account-store.js";
import {
	type Accounts,
	createManagement,
	type Memberships,
	type Tenants,
} from "./accounts/manage.js";
import { createRecords } from "./accounts/records.js";
import type { AuditSink } from "./audit.js";
import { createDevices, type Devices } from "./devices.js";
import type { FactorPlugin } from "./factor.js";
import {
	createLimiter,
	type Limiter,
	type LimiterOptions,
} from "./meter/limiter.js";
import { createMeter } from "./meter/meter.js";
import type { MeterStore } from "./meter/meter-store.js";
import { EMAIL_PROVIDER, type Factor } from "./proof.js";
import { createRecordSeal } from "./record-seal.js";
import { createSealer, type SecretVersion } from "./sealer.js";
import type { EpochStore } from "./session-tokens/epoch-store.js";
import {
	createSessionTokens,
	type SessionTokens,
} from "./session-tokens/session-tokens.js";
import { isStorableText } from "./shared/is-storable-text.js";
import { own } from "./shared/own.js";
import {
	createSignIn,
	type RegistrationPolicyInput,
	type SignIn,
	type SignInPolicyInput,
} from "./sign-in.js";
import type { TokenStore } from "./tokens/token-store.js";
import { createTokens } from "./tokens/tokens.js";

const DEVICE_LIFE_TIME_MILLISECONDS = 400 * 24 * 60 * 60 * 1_000;
const FACTOR_ID = /^[a-z][a-z0-9-]{0,62}$/;

/** The factors of an engine by id, as plugins. */
export type AuthFactors = Readonly<Record<string, FactorPlugin<unknown>>>;

/** What the application may call on each factor, by id. */
export type FactorApis<Factors extends AuthFactors> = {
	readonly [Id in keyof Factors]: Factors[Id] extends FactorPlugin<infer Api>
		? Api
		: never;
};

/** Everything the core needs to run. */
export type AuthOptions<Factors extends AuthFactors = AuthFactors> = {
	/** Tenants, accounts, their identities and memberships. */
	readonly accounts: AccountStore;
	readonly epochs: EpochStore;
	readonly tokenStore: TokenStore;
	readonly meterStore: MeterStore;
	/**
	 * Server secrets for sealed values, session tokens and the seals of
	 * records, newest first. Records sealed under an older secret are sealed
	 * again at their next sign in; keep a secret listed until no record uses
	 * it, or those records stop opening.
	 */
	readonly secrets: readonly SecretVersion[];
	/**
	 * The factors people sign in with, by id. The engine creates each one
	 * once, with tokens and a sealer of its own; a sign in names a factor by
	 * its id and cannot bring one of its own.
	 */
	readonly factors: Factors;
	/**
	 * The providers whose verified emails are believed: such an email links a
	 * new identity to the account that owns it, and makes its owner. A verified
	 * email from any other provider counts as unverified. Every provider listed
	 * must be one a factor of the engine claims. `["email"]` when left out: the
	 * link to the address itself.
	 */
	readonly trustedProviders?: readonly string[] | undefined;
	/** The longest life time of any session token. */
	readonly maximumLifeTimeMilliseconds: number;
	readonly sessionTimeToLiveMilliseconds: number;
	/**
	 * How long a person has to pass the second factor when the policy asks for
	 * one (`requireFactor`). Leave it out and a policy cannot ask: its step-up
	 * verdict becomes a deny.
	 */
	readonly stepUpTimeToLiveMilliseconds?: number | undefined;
	/**
	 * Answers `"allow"` to let a sign in create an account or a membership, or
	 * bring a removed one back; anything else refuses, and nothing is written.
	 * It is required on purpose, like the audit: open registration is a
	 * decision too, `() => "allow"`.
	 */
	readonly registration: (input: RegistrationPolicyInput) => unknown;
	/** Answers `"allow"` to let a subject in; anything else keeps them out. */
	readonly policy: (input: SignInPolicyInput) => unknown;
	/**
	 * Receives the audit record of every security decision of every part. It is
	 * required on purpose: there is no way to build a part without it, so it
	 * cannot be lost. To run without an audit, pass a sink that does nothing.
	 */
	readonly audit: AuditSink;
};

/**
 * The parts of the core, all reporting to the same audit sink. None of them
 * issues a session, a token or a sealed value for the caller: only a sign in
 * with a factor of the engine does.
 */
export type Auth<Factors extends AuthFactors = AuthFactors> = {
	/** The only road to a session. */
	readonly signIn: SignIn;
	/** Checks and revokes session tokens; issuing is the sign-in flow's alone. */
	readonly sessions: Pick<SessionTokens, "verify" | "revoke">;
	/**
	 * Agents that act for a person. A person's session token is turned into an
	 * agent's token with `delegate`; `verify` accepts agent tokens only, and
	 * `sessions.verify` accepts session tokens only, so an application that
	 * does not know about agents never takes one for a person. Revoke an agent,
	 * a delegation, the person, or (for a delegation tied to a session) the
	 * device or session with `sessions.revoke`.
	 */
	readonly agents: Pick<SessionTokens, "delegate"> & {
		readonly verify: SessionTokens["verifyAgent"];
	};
	/** What the application may call on each factor, such as sending a link. */
	readonly factors: FactorApis<Factors>;
	/** Devices with ids the engine chooses, for clients that keep a handle such as a cookie. */
	readonly devices: Devices;
	/**
	 * Creates a limiter for the attempts of the engine's own routes: sign in,
	 * links to send, codes to guess. Give the same limiter to every handler
	 * that needs it; it counts in the meter store of the engine.
	 */
	createLimiter<Input>(
		options: Omit<LimiterOptions<Input>, "meter">,
	): Limiter<Input>;
	/** Tenants: a sign in reaches only one that the application created and did not disable. */
	readonly tenants: Tenants;
	/** Accounts, which only a sign in creates; the application deletes them. */
	readonly accounts: Accounts;
	/** Memberships, which only a sign in creates; the application suspends, removes and restores them. */
	readonly memberships: Memberships;
};

const registerFactors = (
	plugins: AuthFactors,
	capabilitiesFor: (
		id: string,
	) => Parameters<FactorPlugin<unknown>["create"]>[0],
): {
	readonly factors: ReadonlyMap<string, Factor>;
	readonly apis: Readonly<Record<string, unknown>>;
	readonly forget: (account: string) => Promise<void>;
} => {
	const factors = new Map<string, Factor>();
	const apis: Record<string, unknown> = {};
	const forgetters: ((account: string) => Promise<void>)[] = [];

	for (const [id, plugin] of Object.entries(plugins)) {
		if (!FACTOR_ID.test(id)) {
			throw new RangeError(
				`The factor id ${JSON.stringify(id)} must be lower-case letters, digits and dashes, starting with a letter`,
			);
		}

		if (
			!Array.isArray(plugin.providers) ||
			plugin.providers.length === 0 ||
			!plugin.providers.every(isStorableText)
		) {
			throw new RangeError(
				`The factor ${id} must name the providers it may claim`,
			);
		}

		const instance = plugin.create(capabilitiesFor(id));

		factors.set(id, {
			id,
			strength: plugin.strength,
			providers: Object.freeze([...plugin.providers]),
			verify: (response, context) => instance.verify(response, context),
		});
		apis[id] = instance.api;

		const forget = instance.forget;

		if (typeof forget === "function") {
			forgetters.push((account) => forget.call(instance, account));
		}
	}

	return {
		factors,
		apis: Object.freeze(apis),
		async forget(account) {
			for (const forgetOne of forgetters) {
				await forgetOne(account);
			}
		},
	};
};

const requireTrustedProviders = (
	trusted: readonly string[] | undefined,
	factors: ReadonlyMap<string, Factor>,
): readonly string[] => {
	const providers = trusted ?? [EMAIL_PROVIDER];

	if (!Array.isArray(providers) || !providers.every(isStorableText)) {
		throw new RangeError("trustedProviders must be a list of provider names");
	}

	const claimed = new Set(
		Array.from(factors.values()).flatMap((factor) => factor.providers ?? []),
	);

	for (const provider of providers) {
		if (trusted !== undefined && !claimed.has(provider)) {
			throw new RangeError(
				`The trusted provider ${JSON.stringify(provider)} is claimed by no factor of the engine`,
			);
		}
	}

	return Object.freeze([...providers]);
};

/**
 * Builds the core. This is the only way to get its parts: the audit sink is
 * given once and reaches every one of them, so no part can run unaudited. The
 * building blocks themselves are not part of the public API, and no part
 * hands out a way to issue: the keys of the core and of each factor stay
 * inside.
 */
export function createAuth<const Factors extends AuthFactors>(
	options: AuthOptions<Factors>,
): Auth<Factors> {
	const { audit } = options;

	if (typeof audit !== "function") {
		throw new TypeError(
			"audit is required: pass a sink, or one that does nothing to run without an audit",
		);
	}

	if (typeof options.registration !== "function") {
		throw new TypeError(
			'registration is required: a policy for new accounts and memberships, () => "allow" to let anyone in',
		);
	}

	if (typeof options.factors !== "object" || options.factors === null) {
		throw new TypeError(
			"factors is required: the factors people sign in with, by id",
		);
	}

	if (
		options.sessionTimeToLiveMilliseconds > options.maximumLifeTimeMilliseconds
	) {
		throw new RangeError(
			"sessionTimeToLiveMilliseconds must be at most maximumLifeTimeMilliseconds",
		);
	}

	const meter = createMeter({ store: options.meterStore, audit });
	const coreSealer = createSealer({
		secrets: options.secrets,
		domain: "core",
		audit,
	});
	const limiterFor = <Input>(
		limiterOptions: Omit<LimiterOptions<Input>, "meter">,
	): Limiter<Input> => createLimiter({ ...limiterOptions, meter });

	const { factors, apis, forget } = registerFactors(options.factors, (id) => ({
		tokens: createTokens({
			store: options.tokenStore,
			domain: `factor:${id}`,
			audit,
		}),
		sealer: createSealer({
			secrets: options.secrets,
			domain: `factor:${id}`,
			audit,
		}),
		createLimiter: limiterFor,
	}));

	const sessionTokens = createSessionTokens({
		sealer: coreSealer,
		epochs: options.epochs,
		maximumLifeTimeMilliseconds: options.maximumLifeTimeMilliseconds,
		audit,
	});

	const trustedProviders = requireTrustedProviders(
		own(options, "trustedProviders"),
		factors,
	);
	const records = createRecords(createRecordSeal({ secrets: options.secrets }));
	const management = createManagement({
		store: options.accounts,
		records,
		sessionTokens,
		forget,
		audit,
	});

	const signIn = createSignIn({
		factors,
		accounts: options.accounts,
		records,
		trustedProviders,
		sessionTokens,
		tokens: createTokens({ store: options.tokenStore, domain: "core", audit }),
		registration: options.registration,
		policy: options.policy,
		sessionTimeToLiveMilliseconds: options.sessionTimeToLiveMilliseconds,
		stepUpTimeToLiveMilliseconds: options.stepUpTimeToLiveMilliseconds,
		audit,
	});

	return {
		signIn,
		sessions: {
			verify: sessionTokens.verify,
			revoke: sessionTokens.revoke,
		},
		agents: {
			delegate: sessionTokens.delegate,
			verify: sessionTokens.verifyAgent,
		},
		factors: apis as FactorApis<Factors>,
		devices: createDevices({
			sealer: coreSealer,
			timeToLiveMilliseconds: DEVICE_LIFE_TIME_MILLISECONDS,
		}),
		createLimiter: limiterFor,
		tenants: management.tenants,
		accounts: management.accounts,
		memberships: management.memberships,
	};
}
