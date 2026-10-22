const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Why a request was not accepted as coming from a page of the application. */
export type OriginRefusal =
	| "cross-site"
	| "not-a-navigation"
	| "null-origin"
	| "unknown-origin"
	| "no-origin";

/** What the check decided. */
export type OriginVerdict =
	| { readonly ok: true }
	| { readonly ok: false; readonly reason: OriginRefusal };

const originOf = (value: string | null): string | undefined => {
	if (value === null || !URL.canParse(value)) {
		return undefined;
	}

	return new URL(value).origin;
};

/**
 * Decides whether a request that changes something comes from a page of the
 * application, the way OWASP asks for it: the Fetch Metadata of the browser
 * first (a request from another site is refused), then the whole `Origin`
 * (scheme, host and port, never a pattern) against the list. A request with
 * no `Origin` falls back to the origin of its `Referer`, and with neither is
 * accepted only when the browser says it is `same-origin`. `Origin: null`
 * is never accepted. Safe methods are not checked, because they must not
 * change anything.
 */
export const checkOrigin = (
	request: Request,
	allowedOrigins: ReadonlySet<string>,
): OriginVerdict => {
	if (SAFE_METHODS.has(request.method)) {
		return { ok: true };
	}

	const site = request.headers.get("sec-fetch-site");

	if (site === "cross-site") {
		return { ok: false, reason: "cross-site" };
	}

	if (site === "none") {
		return { ok: false, reason: "not-a-navigation" };
	}

	const declared = request.headers.get("origin");

	if (declared === "null") {
		return { ok: false, reason: "null-origin" };
	}

	const origin = originOf(declared) ?? originOf(request.headers.get("referer"));

	if (origin !== undefined) {
		return allowedOrigins.has(origin)
			? { ok: true }
			: { ok: false, reason: "unknown-origin" };
	}

	return site === "same-origin"
		? { ok: true }
		: { ok: false, reason: "no-origin" };
};

/** Checks a list of origins when the handler is made: each must be exactly `scheme://host[:port]`, https unless it is loopback. */
export const parseOrigins = (
	name: string,
	origins: readonly string[],
): ReadonlySet<string> => {
	const parsed = new Set<string>();

	for (const entry of origins) {
		const url = URL.canParse(entry) ? new URL(entry) : undefined;
		const loopback =
			url !== undefined &&
			["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

		if (
			url === undefined ||
			url.origin !== entry ||
			url.hostname.includes("*") ||
			(url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
		) {
			throw new RangeError(
				`${name} entry "${entry}" must be an origin like https://app.example.com, with nothing after it (http only for loopback)`,
			);
		}

		parsed.add(url.origin);
	}

	return parsed;
};
