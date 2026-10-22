import { hasControlOrSpace } from "../shared/has-control-or-space.js";

const LOCAL_PART = /^[\p{L}\p{N}!#$%&'*+/=?^_`{|}~.-]+$/u;
const FORBIDDEN_DOMAIN_CHARACTERS = new Set(":/?#[]\\%");
const MAXIMUM_INPUT_CHARACTERS = 1_024;
const MAXIMUM_ADDRESS_BYTES = 254;
const MAXIMUM_LOCAL_PART_BYTES = 64;
const MAXIMUM_DOMAIN_BYTES = 253;
const MAXIMUM_LABEL_BYTES = 63;

const encoder = new TextEncoder();

const byteLength = (text: string): number => encoder.encode(text).length;

const isValidLocalPart = (local: string): boolean => {
	return (
		LOCAL_PART.test(local) &&
		!local.startsWith(".") &&
		!local.endsWith(".") &&
		!local.includes("..") &&
		byteLength(local) <= MAXIMUM_LOCAL_PART_BYTES
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

	const labels = url.hostname.split(".");
	const lastLabel = labels.at(-1);

	if (
		url.hostname.length > MAXIMUM_DOMAIN_BYTES ||
		lastLabel === undefined ||
		!Number.isNaN(Number(lastLabel)) ||
		labels.some(
			(label) => label.length === 0 || label.length > MAXIMUM_LABEL_BYTES,
		)
	) {
		return undefined;
	}

	return url.hostname;
};

const CANONICAL = Symbol("canonical-email");

/**
 * An email address in canonical form. Only `canonicalizeEmail` creates one:
 * the brand is a symbol nobody else can name, so a value of this type has been
 * validated and normalized (NFKC, trimmed, a lower case local part, a punycode
 * domain, the length limits of RFC 5321). Stores take this type, so an address
 * that was never canonicalized cannot be compared or kept. The value is frozen.
 */
export type CanonicalEmail = {
	readonly address: string;
	readonly [CANONICAL]: true;
};

/**
 * Returns the canonical form of an address, or `undefined` when it is not an
 * acceptable address. The domain is processed by the URL host parser, which
 * implements UTS #46 (case mapping and punycode), so it is not lowercased
 * here: lowercasing first could disagree with it, for example on a final
 * sigma. Quoted local parts and comments are legal in RFC 5322 but refused on
 * purpose: they are rare and ambiguous, and they are how an address smuggles
 * a second recipient or a header into a message. Addresses longer than 254
 * bytes, local parts over 64, labels over 63 and domains over 253 are refused.
 */
export const canonicalizeEmail = (
	email: string,
): CanonicalEmail | undefined => {
	if (email.length > MAXIMUM_INPUT_CHARACTERS) {
		return undefined;
	}

	const parts = email.normalize("NFKC").trim().split("@");

	if (parts.length !== 2) {
		return undefined;
	}

	const [rawLocal, domain] = parts;
	const local = rawLocal?.toLowerCase();

	if (local === undefined || domain === undefined || !isValidLocalPart(local)) {
		return undefined;
	}

	const canonicalDomain = canonicalizeDomain(domain);

	if (canonicalDomain === undefined) {
		return undefined;
	}

	const address = `${local}@${canonicalDomain}`;

	if (byteLength(address) > MAXIMUM_ADDRESS_BYTES) {
		return undefined;
	}

	const canonical: CanonicalEmail = { address, [CANONICAL]: true };

	return Object.freeze(canonical);
};
