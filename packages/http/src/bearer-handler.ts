import { readBearerToken } from "./credentials.js";
import {
	answer,
	createHandler,
	type HandlerOptions,
	type Mode,
} from "./handler.js";
import { parseOrigins } from "./origin.js";

const MINIMUM_DEVICE_CHARACTERS = 16;
const PREFLIGHT_MAXIMUM_AGE_SECONDS = 600;

/** Options of the handler for clients that carry a token themselves. */
export type BearerHandlerOptions = HandlerOptions & {
	/**
	 * The origins of browser pages that may call the API (CORS): exact origins,
	 * never patterns. Empty when no page in a browser calls it, only apps and
	 * servers. A token that a page keeps in script can be read by any script
	 * of that page, so a page of your own is better served by the handler for
	 * browsers.
	 */
	readonly allowedOrigins: readonly string[];
};

/**
 * Creates the handler for clients that carry a token themselves, such as a
 * mobile app or a server. Signing in returns the token in the body and the
 * handler never sets a cookie; it reads only the header Authorization with
 * the scheme Bearer and ignores cookies altogether, so a browser cannot be
 * made to speak for a person. There is no ambient credential to forge, so no
 * check of the origin is made; the list of origins is the list of CORS. A
 * client says which device it is with a random, unique device in the body of
 * a sign in: it decides what signing out of a device ends, so it must not be
 * a name such as "phone".
 */
export function createBearerHandler(
	options: BearerHandlerOptions,
): (request: Request) => Promise<Response> {
	const origins = parseOrigins("allowedOrigins", options.allowedOrigins);

	const allowedOriginOf = (request: Request): string | undefined => {
		const origin = request.headers.get("origin");

		return origin !== null && origins.has(origin) ? origin : undefined;
	};

	const mode: Mode = {
		guard: () => undefined,
		preflight: (request) => {
			const origin = allowedOriginOf(request);

			return origin === undefined
				? answer(403, { error: "forbidden" })
				: new Response(null, {
						status: 204,
						headers: {
							"access-control-allow-origin": origin,
							"access-control-allow-methods": "GET, POST",
							"access-control-allow-headers": "authorization, content-type",
							"access-control-max-age": String(PREFLIGHT_MAXIMUM_AGE_SECONDS),
							vary: "origin",
						},
					});
		},
		decorate: (request, response) => {
			const origin = allowedOriginOf(request);

			response.headers.append("vary", "origin");

			if (origin !== undefined) {
				response.headers.set("access-control-allow-origin", origin);
				response.headers.set("access-control-expose-headers", "retry-after");
			}

			return response;
		},
		tokenOf: readBearerToken,
		async deviceFor(_request, body) {
			const device = body.device;

			return typeof device === "string" &&
				device.length >= MINIMUM_DEVICE_CHARACTERS
				? { device, cookies: [] }
				: undefined;
		},
		signedIn: (signedIn) =>
			answer(200, {
				token: signedIn.token,
				subject: signedIn.subject,
				tenant: signedIn.tenant,
				device: signedIn.device,
				session: signedIn.session,
				identity: signedIn.identity,
				email: signedIn.email,
			}),
		sessionEnded: () => [],
	};

	return createHandler(options, mode);
}
