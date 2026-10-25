import type { Limiter, LimiterOptions } from "./meter/limiter.js";
import type { FactorContext, ProofStrength } from "./proof.js";
import type { Result } from "./result.js";
import type { Sealer } from "./sealer.js";
import type { Tokens } from "./tokens/tokens.js";

/**
 * What the engine gives one factor when it creates it, and nobody else.
 * Tokens and sealed values live in the factor's own domain: no other factor,
 * no handler and not the application can issue a token this factor redeems
 * or seal a value it opens, and none of them reaches the core's own.
 */
export type FactorCapabilities = {
	readonly tokens: Tokens;
	readonly sealer: Sealer;
	/** A limiter that counts in the engine's meter store. */
	createLimiter<Input>(
		options: Omit<LimiterOptions<Input>, "meter">,
	): Limiter<Input>;
};

/** A factor as the engine runs it, created from its plugin. */
export type FactorInstance<Api> = {
	/** Checks the response of the person and answers claims; never a session. */
	verify(response: unknown, context: FactorContext): Promise<Result<unknown>>;
	/** What the application may call, such as sending a link; nothing that issues. */
	readonly api: Api;
	/** Forgets what the factor keeps for an account; the engine calls it when the account is deleted. */
	forget?(account: string): Promise<void>;
};

/**
 * A factor as a plugin hands it to `createAuth`. The engine creates it once,
 * with capabilities of its own, and signs people in with it by its id only:
 * a sign in cannot bring a factor of its own. A factor may claim identities
 * of the providers it names and of no other, so a factor written for one
 * provider can never speak for the accounts of another.
 */
export type FactorPlugin<Api> = {
	readonly strength: ProofStrength;
	/** The providers whose identities this factor may claim, such as `email`. */
	readonly providers: readonly string[];
	create(capabilities: FactorCapabilities): FactorInstance<Api>;
};
