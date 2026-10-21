const LOCAL_PART = /^[\p{L}\p{N}!#$%&'*+/=?^_`{|}~.-]+$/u;
const FORBIDDEN_DOMAIN_CHARACTERS = new Set(":/?#[]\\%");
const LAST_CODE_UNIT_OF_CONTROL_RANGE = 0x20;
const DELETE_CODE_UNIT = 0x7f;

const hasControlOrSpace = (text: string): boolean => {
	for (let index = 0; index < text.length; index += 1) {
		const codeUnit = text.charCodeAt(index);

		if (
			codeUnit <= LAST_CODE_UNIT_OF_CONTROL_RANGE ||
			codeUnit === DELETE_CODE_UNIT
		) {
			return true;
		}
	}

	return false;
};

const isValidLocalPart = (local: string): boolean => {
	return (
		LOCAL_PART.test(local) &&
		!local.startsWith(".") &&
		!local.endsWith(".") &&
		!local.includes("..")
	);
};

const canonicalizeDomain = (domain: string): string | undefined => {
	if (
		domain.length === 0 ||
		hasControlOrSpace(domain) ||
		Array.from(domain).some((character) =>
			FORBIDDEN_DOMAIN_CHARACTERS.has(character),
		)
	) {
		return undefined;
	}

	let url: URL;

	try {
		url = new URL(`http://${domain}`);
	} catch {
		return undefined;
	}

	const lastLabel = url.hostname.split(".").at(-1);

	if (lastLabel === undefined || !Number.isNaN(Number(lastLabel))) {
		return undefined;
	}

	return url.hostname;
};

const CANONICAL = Symbol("canonical-email");

/**
 * An email address in canonical form. Only `canonicalizeEmail` creates one:
 * the brand is a symbol nobody else can name, so a value of this type has been
 * validated and normalized (NFKC, trimmed, lower case, a strict local part, a
 * punycode domain). Stores take this type, so an address that was never
 * canonicalized cannot be compared or kept.
 */
export type CanonicalEmail = {
	readonly address: string;
	readonly [CANONICAL]: true;
};

/** Returns the canonical form of an address, or `undefined` when it is not an acceptable address. */
export const canonicalizeEmail = (
	email: string,
): CanonicalEmail | undefined => {
	const parts = email.normalize("NFKC").trim().toLowerCase().split("@");

	if (parts.length !== 2) {
		return undefined;
	}

	const [local, domain] = parts;

	if (local === undefined || domain === undefined || !isValidLocalPart(local)) {
		return undefined;
	}

	const canonicalDomain = canonicalizeDomain(domain);

	if (canonicalDomain === undefined) {
		return undefined;
	}

	const canonical: CanonicalEmail = {
		address: `${local}@${canonicalDomain}`,
		[CANONICAL]: true,
	};

	return Object.freeze(canonical);
};
