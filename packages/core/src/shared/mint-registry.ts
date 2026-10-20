export type MintRegistry<Minted extends object> = {
	mint(value: Minted): Minted;
	has(value: unknown): value is Minted;
};

export const createMintRegistry = <
	Minted extends object,
>(): MintRegistry<Minted> => {
	const minted = new WeakSet<object>();

	return {
		mint(value) {
			minted.add(value);

			return value;
		},
		has(value): value is Minted {
			return typeof value === "object" && value !== null && minted.has(value);
		},
	};
};
