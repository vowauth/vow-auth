const CANNOT_BE_STORED = /[\p{Cc}\p{Cs}]/u;

/**
 * Whether a value is text that every store can keep: not empty, and without
 * control characters (NUL among them) or lone surrogates, which a Postgres
 * text column refuses. Spaces, emoji and joiners are fine. Identifiers that
 * come from outside (tenant, device, a provider's id of a person, an agent's
 * name) are checked with it at the border, so the stores see the same values
 * whatever they are made of.
 */
export const isStorableText = (value: unknown): value is string => {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		!CANNOT_BE_STORED.test(value)
	);
};
