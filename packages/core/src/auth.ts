import type { AuditSink } from "./audit.js";
import type { IdentityStore } from "./identity/identity-store.js";
import {
	createMutateIdentity,
	type MutateIdentity,
} from "./identity/mutate-identity.js";
import { createMeter, type Meter } from "./meter/meter.js";
import type { MeterStore } from "./meter/meter-store.js";
import { createSealer, type Sealer, type SecretVersion } from "./sealer.js";
import type { EpochStore } from "./session-tokens/epoch-store.js";
import {
	createSessionTokens,
	type SessionTokens,
} from "./session-tokens/session-tokens.js";
import {
	createSignIn,
	type SignIn,
	type SignInPolicyInput,
} from "./sign-in.js";
import type { TokenStore } from "./tokens/token-store.js";
import { createTokens, type Tokens } from "./tokens/tokens.js";

/** Everything the core needs to run. */
export type AuthOptions = {
	readonly identities: IdentityStore;
	readonly epochs: EpochStore;
	readonly tokenStore: TokenStore;
	readonly meterStore: MeterStore;
	/** Server secrets for sealed values and session tokens, newest first. */
	readonly secrets: readonly SecretVersion[];
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

/** The parts of the core, all reporting to the same audit sink. */
export type Auth = {
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
	/** One-time secrets bound to a purpose, for factors such as an email link. */
	readonly tokens: Tokens;
	/** Seals short-lived values such as an OAuth state. */
	readonly sealer: Sealer;
	/** Counts requests against limits shared by every instance. */
	readonly meter: Meter;
	/** Deletes subjects and confirms emails, with every consequence. */
	readonly mutateIdentity: MutateIdentity;
};

/**
 * Builds the core. This is the only way to get its parts: the audit sink is
 * given once and reaches every one of them, so no part can run unaudited. The
 * building blocks themselves are not part of the public API.
 */
export function createAuth(options: AuthOptions): Auth {
	const { audit } = options;

	if (typeof audit !== "function") {
		throw new TypeError(
			"audit is required: pass a sink, or one that does nothing to run without an audit",
		);
	}

	if (
		options.sessionTimeToLiveMilliseconds > options.maximumLifeTimeMilliseconds
	) {
		throw new RangeError(
			"sessionTimeToLiveMilliseconds must be at most maximumLifeTimeMilliseconds",
		);
	}

	const sealer = createSealer({ secrets: options.secrets, audit });
	const tokens = createTokens({ store: options.tokenStore, audit });
	const meter = createMeter({ store: options.meterStore, audit });

	const sessionTokens = createSessionTokens({
		sealer,
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
		identities: options.identities,
		sessionTokens,
		mutateIdentity,
		tokens,
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
		tokens,
		meter,
		sealer,
		mutateIdentity,
	};
}
