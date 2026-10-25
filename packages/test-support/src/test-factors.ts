import type {
	FactorContext,
	FactorPlugin,
	ProofStrength,
	Result,
} from "@vow-auth/core";

/** A factor plugin for a test, whose check is the given function. */
export const factorPluginOf = (
	verify: (
		response: unknown,
		context: FactorContext,
	) => Promise<Result<unknown>>,
	options: {
		readonly strength?: ProofStrength;
		readonly providers?: readonly string[];
	} = {},
): FactorPlugin<Record<string, never>> => ({
	strength: options.strength ?? "possession",
	providers: options.providers ?? ["email"],
	create: () => ({ verify, api: {} }),
});
