export type MintRegistry<Minted extends object> = {
	mint(value: Minted): Readonly<Minted>;
	has(value: unknown): value is Minted;
};

/**
 * A registry of the values the core created itself. `has` tells a value the
 * core vouched for from a look-alike (a decision, a session or a proof rebuilt
 * from JSON or written by hand) by identity, not by shape. `mint` freezes the
 * value first: nobody can change what the core vouched for afterwards, for
 * example turn the subject of an allow into another one.
 */
export const createMintRegistry = <
	Minted extends object,
>(): MintRegistry<Minted> => {
	const minted = new WeakSet<object>();

	return {
		mint(value) {
			const frozen = Object.freeze(value);

			minted.add(frozen);

			return frozen;
		},
		has(value): value is Minted {
			return typeof value === "object" && value !== null && minted.has(value);
		},
	};
};
