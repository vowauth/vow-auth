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

export const canonicalizeEmail = (email: string): string | undefined => {
	const parts = email.normalize("NFKC").trim().toLowerCase().split("@");

	if (parts.length !== 2) {
		return undefined;
	}

	const [local, domain] = parts;

	if (local === undefined || domain === undefined || !isValidLocalPart(local)) {
		return undefined;
	}

	const canonicalDomain = canonicalizeDomain(domain);

	return canonicalDomain === undefined
		? undefined
		: `${local}@${canonicalDomain}`;
};
