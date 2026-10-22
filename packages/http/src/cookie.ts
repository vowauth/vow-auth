/** Where the browser may send a cookie, by the site that asks. */
export type SameSite = "lax" | "strict";

/** What a cookie of the library looks like on the wire. */
export type CookieSettings = {
	readonly name: string;
	readonly sameSite: SameSite;
	/** `false` only for a page on http://localhost, where a browser accepts no `Secure` cookie. */
	readonly secure: boolean;
	readonly maxAgeSeconds: number;
};

const TOKEN_CHARACTER = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const COOKIE_VALUE = /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/;
const HOST_PREFIX = "__Host-";

const SAME_SITE_ATTRIBUTES: Readonly<Record<SameSite, string>> = {
	lax: "SameSite=Lax",
	strict: "SameSite=Strict",
};

const attributesOf = (settings: CookieSettings, maxAgeSeconds: number) => {
	if (!TOKEN_CHARACTER.test(settings.name)) {
		throw new RangeError("A cookie name must be an HTTP token");
	}

	if (settings.name.startsWith(HOST_PREFIX) && !settings.secure) {
		throw new RangeError("A __Host- cookie must be Secure");
	}

	return [
		`Max-Age=${maxAgeSeconds}`,
		"Path=/",
		...(settings.secure ? ["Secure"] : []),
		"HttpOnly",
		SAME_SITE_ATTRIBUTES[settings.sameSite],
	].join("; ");
};

/**
 * Writes a `Set-Cookie` header: `HttpOnly`, an explicit `SameSite`, the path
 * `/` and no `Domain`, so the cookie belongs to this host alone, and `Secure`
 * unless the page is on http://localhost. A value that a header cannot carry
 * is refused with a `RangeError` instead of being escaped: the values of the
 * library are base64url text, so anything else is a bug.
 */
export const serializeCookie = (
	settings: CookieSettings,
	value: string,
): string => {
	if (!COOKIE_VALUE.test(value)) {
		throw new RangeError(
			"A cookie value must hold only cookie-safe characters",
		);
	}

	return `${settings.name}=${value}; ${attributesOf(settings, settings.maxAgeSeconds)}`;
};

/** Writes the `Set-Cookie` header that makes a browser forget a cookie, with the same attributes it was set with. */
export const clearCookie = (settings: CookieSettings): string => {
	return `${settings.name}=; ${attributesOf(settings, 0)}`;
};

/**
 * Reads one cookie of a request. A name that appears twice is ambiguous (a
 * sibling subdomain may have planted the second one), so it reads as absent.
 */
export const readCookie = (
	request: Request,
	name: string,
): string | undefined => {
	const found: string[] = [];

	for (const part of (request.headers.get("cookie") ?? "").split(";")) {
		const separator = part.indexOf("=");

		if (separator !== -1 && part.slice(0, separator).trim() === name) {
			found.push(part.slice(separator + 1).trim());
		}
	}

	return found.length === 1 && found[0] !== "" ? found[0] : undefined;
};
