import type { AuditSink } from "./audit.js";
import { createDevices, type Devices } from "./devices.js";
import { ERROR_CODES } from "./errors.js";
import type { FactorPlugin } from "./factor.js";
import type { IdentityStore } from "./identity/identity-store.js";
import {
	createMutateIdentity,
	IDENTITY_CHANGE_TYPES,
	type MutationOutcome,
} from "./identity/mutate-identity.js";
import {
	createLimiter,
	type Limiter,
	type LimiterOptions,
} from "./meter/limiter.js";
import { createMeter } from "./meter/meter.js";
import type { MeterStore } from "./meter/meter-store.js";
import type { Factor } from "./proof.js";
import { fail, type Result } from "./result.js";
import { createSealer, type SecretVersion } from "./sealer.js";
import type { EpochStore } from "./session-tokens/epoch-store.js";
import {
	createSessionTokens,
	type SessionTokens,
} from "./session-tokens/session-tokens.js";
import { isStorableText } from "./shared/is-storable-text.js";
import {
	createSignIn,
	type SignIn,
	type SignInPolicyInput,
} from "./sign-in.js";
import type { TokenStore } from "./tokens/token-store.js";
import { createTokens } from "./tokens/tokens.js";

const DEVICE_LIFE_TIME_MILLISECONDS = 400 * 24 * 60 * 60 * 1_000;

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
	readonly identities: IdentityStore;
	readonly epochs: EpochStore;
	readonly tokenStore: TokenStore;
	readonly meterStore: MeterStore;
	/** Server secrets for sealed values and session tokens, newest first. */
	readonly secrets: readonly SecretVersion[];
	/**
	 * The factors people sign in with, by id. The engine creates each one
	 * once, with tokens and a sealer of its own; a sign in names a factor by
	 * its id and cannot bring one of its own.
	 */
	readonly factors: Factors;
	/** The longest life time of any session token. */
	readonly maximumLifeTimeMilliseconds: number;
	readonly sessionTimeToLiveMilliseconds: number;
	/**
	 * How long a person has to pass the second factor when the policy asks for
	 * one (`requireFactor`). Leave it out and a policy cannot ask: its step-up
	 * verdict becomes a deny.
	 */
	readonly stepUpTimeToLiveMilliseconds?: number | undefined;
	/** Answers `"allow"` to let a subject in; anything else keeps them out. */
	readonly policy: (input: SignInPolicyInput) => unknown;
	/**
	 * Receives the audit record of every security decision of every part. It is
	 * required on purpose: there is no way to build a part without it, so it
	 * cannot be lost. To run without an audit, pass a sink that does nothing.
	 */
	readonly audit: AuditSink;
};

/** The change of a subject the application may ask for. */
export type SubjectChange = {
	readonly type: typeof IDENTITY_CHANGE_TYPES.delete;
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
	/**
	 * Deletes a subject with every consequence. Confirming an email is not
	 * here: a sign in with a verified email does it, with a proof only a
	 * factor of the engine can give.
	 */
	mutateIdentity(
		tenant: string,
		subject: string,
		change: SubjectChange,
	): Promise<Result<MutationOutcome>>;
};

const registerFactors = (
	plugins: AuthFactors,
	capabilitiesFor: (
		id: string,
	) => Parameters<FactorPlugin<unknown>["create"]>[0],
): {
	readonly factors: ReadonlyMap<string, Factor>;
	readonly apis: Readonly<Record<string, unknown>>;
} => {
	const factors = new Map<string, Factor>();
	const apis: Record<string, unknown> = {};

	for (const [id, plugin] of Object.entries(plugins)) {
		if (!isStorableText(id)) {
			throw new RangeError(
				`The factor id ${JSON.stringify(id)} cannot be stored`,
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
	}

	return { factors, apis: Object.freeze(apis) };
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

	const { factors, apis } = registerFactors(options.factors, (id) => ({
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

	const mutateIdentity = createMutateIdentity({
		store: options.identities,
		sessionTokens,
		audit,
	});

	const signIn = createSignIn({
		factors,
		identities: options.identities,
		sessionTokens,
		mutateIdentity,
		tokens: createTokens({ store: options.tokenStore, domain: "core", audit }),
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
		async mutateIdentity(tenant, subject, change) {
			return change?.type === IDENTITY_CHANGE_TYPES.delete
				? mutateIdentity(tenant, subject, {
						type: IDENTITY_CHANGE_TYPES.delete,
					})
				: fail(ERROR_CODES.invalidRequest);
		},
	};
}
