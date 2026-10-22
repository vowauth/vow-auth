import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { isPublicAddress } from "./public-address.js";

const HTTPS = "https:";
const HOST_NAME =
	/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

/** Options for the outbound guard. */
export type OutboundGuardOptions = {
	/**
	 * The host names the application may call, exactly, in lower case, without
	 * a scheme or a port. Nothing else is reachable, and an IP address is never
	 * accepted as a host.
	 */
	readonly allowedHosts: readonly string[];
	/**
	 * Resolves a host name to its addresses. When it is given, every address
	 * must be public, or the call is refused. The check and the later
	 * connection resolve separately, so this narrows DNS rebinding but does
	 * not close it: the closing measure is a restriction of outbound traffic
	 * in the network, which the application has to set up.
	 */
	readonly resolveAddresses?: (host: string) => Promise<readonly string[]>;
	readonly fetch?: typeof fetch;
};

/** What the guard does with a URL. */
export type OutboundGuard = {
	check(target: unknown): Promise<Result<URL>>;
	fetch(
		target: unknown,
		init?: Omit<RequestInit, "redirect">,
	): Promise<Result<Response>>;
};

const parseAllowedHost = (entry: string): string => {
	const canonical = URL.canParse(`https://${entry}`)
		? new URL(`https://${entry}`).hostname
		: undefined;

	if (canonical !== entry || !HOST_NAME.test(entry) || /^[\d.]+$/.test(entry)) {
		throw new RangeError(
			`allowedHosts entry "${entry}" must be a lower case host name without scheme, port or address`,
		);
	}

	return canonical;
};

/**
 * Creates the guard for calls the application makes to addresses it did not
 * choose alone, such as webhooks. It follows the OWASP rules: an allowlist
 * first, https only, the default port, no credentials, no IP address as a
 * host, public addresses only when the names are resolved, and no redirect
 * followed. Every refusal is `forbidden`; a network failure of `fetch` is
 * `unavailable`.
 */
export function createOutboundGuard(
	options: OutboundGuardOptions,
): OutboundGuard {
	const hosts = new Set(options.allowedHosts.map(parseAllowedHost));
	const fetchImplementation = options.fetch ?? fetch;

	const check = async (target: unknown): Promise<Result<URL>> => {
		if (typeof target !== "string" || !URL.canParse(target)) {
			return fail(ERROR_CODES.forbidden);
		}

		const url = new URL(target);

		if (
			url.protocol !== HTTPS ||
			url.port !== "" ||
			url.username !== "" ||
			url.password !== "" ||
			!hosts.has(url.hostname)
		) {
			return fail(ERROR_CODES.forbidden);
		}

		if (options.resolveAddresses !== undefined) {
			try {
				const addresses = await options.resolveAddresses(url.hostname);

				if (addresses.length === 0 || !addresses.every(isPublicAddress)) {
					return fail(ERROR_CODES.forbidden);
				}
			} catch {
				return fail(ERROR_CODES.forbidden);
			}
		}

		return succeed(url);
	};

	return {
		check,
		async fetch(target, init) {
			const checked = await check(target);

			if (!checked.ok) {
				return checked;
			}

			try {
				return succeed(
					await fetchImplementation(checked.value, {
						...init,
						redirect: "error",
						cache: "no-store",
					}),
				);
			} catch {
				return fail(ERROR_CODES.unavailable);
			}
		},
	};
}
