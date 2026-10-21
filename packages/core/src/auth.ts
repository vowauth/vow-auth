import type { AuditSink } from "./audit.js";
import type { IdentityStore } from "./identity/identity-store.js";
import {
	createMutateIdentity,
	type MutateIdentity,
} from "./identity/mutate-identity.js";
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
	/** Server secrets for sealed values and session tokens, newest first. */
	readonly secrets: readonly SecretVersion[];
	/** The longest life time of any session token. */
	readonly maximumLifeTimeMilliseconds: number;
	readonly sessionTimeToLiveMilliseconds: number;
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
	/** One-time secrets bound to a purpose, for factors such as an email link. */
	readonly tokens: Tokens;
	/** Seals short-lived values such as an OAuth state. */
	readonly sealer: Sealer;
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

	const sealer = createSealer({ secrets: options.secrets, audit });
	const tokens = createTokens({ store: options.tokenStore, audit });
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
		policy: options.policy,
		sessionTimeToLiveMilliseconds: options.sessionTimeToLiveMilliseconds,
		audit,
	});

	return {
		signIn,
		sessions: {
			verify: sessionTokens.verify,
			revoke: sessionTokens.revoke,
		},
		tokens,
		sealer,
		mutateIdentity,
	};
}
