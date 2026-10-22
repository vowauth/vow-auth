const BEARER = /^bearer ([A-Za-z0-9\-._~+/]+=*)$/i;
const MAXIMUM_ADDRESS_CHARACTERS = 64;
const IPV6_GROUPS = 8;
const PREFIX_GROUPS = 4;

/**
 * Reads the token of an `Authorization: Bearer` header. The scheme is not
 * case sensitive and the token must be the one thing after it (RFC 6750); a
 * second header, a second token or anything else reads as no token. Never the
 * query: a token in a URL ends up in logs and in `Referer`.
 */
export const readBearerToken = (request: Request): string | undefined => {
	const match = BEARER.exec(request.headers.get("authorization") ?? "");

	return match?.[1];
};

const expandIpv6 = (address: string): readonly string[] | undefined => {
	const halves = address.split("::");

	if (halves.length > 2) {
		return undefined;
	}

	const groupsOf = (side: string | undefined): string[] =>
		side === undefined || side === "" ? [] : side.split(":");
	const head = groupsOf(halves[0]);
	const tail = groupsOf(halves[1]);
	const missing = IPV6_GROUPS - head.length - tail.length;

	if (halves.length === 1) {
		return head.length === IPV6_GROUPS ? head : undefined;
	}

	return missing >= 1
		? [...head, ...new Array<string>(missing).fill("0"), ...tail]
		: undefined;
};

/**
 * Reads the address of the client from the one header that the application
 * names, such as `cf-connecting-ip` behind Cloudflare. The library never
 * picks a header itself: `X-Forwarded-For` can be written by the client unless
 * the proxy replaces it, and only the application knows its proxy. The value
 * must be a single address. An IPv6 address is cut to its /64 prefix, because
 * one client holds billions of addresses inside it and a limit per address
 * would never stop it. The answer is a key for a limit; no header, or one that
 * is not an address, gives `undefined`.
 */
export const clientAddress = (
	request: Request,
	options: { readonly header: string },
): string | undefined => {
	const value = request.headers.get(options.header)?.trim();

	if (
		value === undefined ||
		value === "" ||
		value.length > MAXIMUM_ADDRESS_CHARACTERS
	) {
		return undefined;
	}

	if (!value.includes(":")) {
		return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) ? value : undefined;
	}

	if (!/^[0-9a-fA-F:]+$/.test(value)) {
		return undefined;
	}

	const groups = expandIpv6(value.toLowerCase());

	return groups === undefined || groups.some((group) => group.length > 4)
		? undefined
		: `${groups
				.slice(0, PREFIX_GROUPS)
				.map((group) => group.replace(/^0+(?=.)/, ""))
				.join(":")}::/64`;
};
