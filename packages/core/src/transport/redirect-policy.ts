import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { hasControlOrSpace } from "../shared/has-control-or-space.js";

const MAXIMUM_TARGET_CHARACTERS = 2_048;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const BACKSLASH = "\\";
const ORIGIN_HOST = /^([a-z0-9][a-z0-9.-]*|\[[0-9a-f:]+\])$/;

/** Options for the redirect policy. */
export type RedirectPolicyOptions = {
	/**
	 * Origins a redirect may lead to, each written as `scheme://host[:port]`
	 * with nothing after it. There are no patterns: an origin matches exactly
	 * or not at all. `http` is accepted only for a loopback host.
	 */
	readonly allowedOrigins: readonly string[];
};

const parseAllowedOrigin = (entry: string): string => {
	const url = URL.canParse(entry) ? new URL(entry) : undefined;

	if (
		url === undefined ||
		url.origin !== entry ||
		!ORIGIN_HOST.test(url.hostname) ||
		(url.protocol !== "https:" &&
			!(url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)))
	) {
		throw new RangeError(
			`allowedOrigins entry "${entry}" must be an https origin (http only for loopback) with no path`,
		);
	}

	return url.origin;
};

/**
 * Creates the check for where a flow may send the browser next, such as the
 * address to return to after a sign in. A target is accepted when it is a path
 * on this site (one leading slash) or an absolute URL whose origin is in the
 * list, exactly. Everything else is refused with `invalid-request`: patterns
 * are not supported because they are how matching goes wrong (RFC 9700
 * section 4.1), and a target with credentials, a backslash, a space or a
 * control character is refused because the browser reads it differently from
 * a validator. The result carries the target to redirect to.
 */
export function createRedirectPolicy(
	options: RedirectPolicyOptions,
): (target: unknown) => Result<string> {
	const origins = new Set(options.allowedOrigins.map(parseAllowedOrigin));

	return (target) => {
		if (
			typeof target !== "string" ||
			target.length === 0 ||
			target.length > MAXIMUM_TARGET_CHARACTERS ||
			target.includes(BACKSLASH) ||
			hasControlOrSpace(target)
		) {
			return fail(ERROR_CODES.invalidRequest);
		}

		if (target.startsWith("/")) {
			return target.startsWith("//")
				? fail(ERROR_CODES.invalidRequest)
				: succeed(target);
		}

		const url = URL.canParse(target) ? new URL(target) : undefined;

		if (
			url === undefined ||
			url.username !== "" ||
			url.password !== "" ||
			!origins.has(url.origin)
		) {
			return fail(ERROR_CODES.invalidRequest);
		}

		return succeed(url.href);
	};
}
