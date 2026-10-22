import { type Auth, defineDuration } from "@vow-auth/core";
import {
	type CookieSettings,
	clearCookie,
	readCookie,
	type SameSite,
	serializeCookie,
} from "./cookie.js";
import {
	answer,
	createHandler,
	type DeviceChoice,
	type HandlerOptions,
	type Mode,
} from "./handler.js";
import { checkOrigin, parseOrigins } from "./origin.js";

const DEVICE_PURPOSE = "device";
const DEVICE_ID_BYTES = 16;
const DEVICE_MAXIMUM_AGE_SECONDS = 400 * 24 * 60 * 60;
const HOST_PREFIX = "__Host-";
const SESSION_COOKIE = "vow-session";
const DEVICE_COOKIE = "vow-device";
const DEVICE_ID = /^[0-9a-f]{32}$/;

/** Options of the handler for browsers. */
export type CookieHandlerOptions = Omit<HandlerOptions, "auth"> & {
	readonly auth: Pick<Auth, "signIn" | "sessions" | "sealer">;
	/**
	 * The origin the application is served from, such as
	 * https://app.example.com. It decides the Secure attribute and the prefix
	 * __Host- of the cookies, so no header of a proxy is trusted for it. Only
	 * a page on http://localhost may use http.
	 */
	readonly origin: string;
	/** Other origins whose pages may post to the handler, besides origin; exact origins, never patterns. */
	readonly allowedOrigins?: readonly string[];
	/** How long the cookie of a session lives; the life time of the sessions of createAuth. */
	readonly sessionMaximumAgeSeconds: number;
	/**
	 * Lax (the default) lets a link from another site open a page of a person
	 * who is signed in. Strict refuses the cookie on every request that starts
	 * on another site, such a link included. The cookie of a flow that returns
	 * from another site (OAuth) is Lax in both cases.
	 */
	readonly sameSite?: SameSite;
};

const randomHex = (bytes: number): string => {
	return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
};

/**
 * Creates the handler for browsers. The token of a session lives only in a
 * cookie that script cannot read (HttpOnly, Secure, __Host-, an explicit
 * SameSite) and never appears in a body. A request that changes something
 * must come from a page of the application (Fetch Metadata and the whole
 * Origin) and carry JSON, so another site cannot post to it, and the header
 * Authorization is not read at all. Each browser gets a random device id in a
 * sealed cookie, so signing out of a device ends this browser and no other.
 */
export function createCookieHandler(
	options: CookieHandlerOptions,
): (request: Request) => Promise<Response> {
	const { auth, sessionMaximumAgeSeconds } = options;
	const origins = parseOrigins("origin", [
		options.origin,
		...(options.allowedOrigins ?? []),
	]);
	const secure = options.origin.startsWith("https:");
	const deviceLife = defineDuration(DEVICE_MAXIMUM_AGE_SECONDS * 1_000);

	if (!origins.has(options.origin) || !deviceLife.ok) {
		throw new RangeError("origin must be an origin, without a path");
	}

	if (
		!Number.isSafeInteger(sessionMaximumAgeSeconds) ||
		sessionMaximumAgeSeconds <= 0
	) {
		throw new RangeError("sessionMaximumAgeSeconds must be a positive integer");
	}

	const prefix = secure ? HOST_PREFIX : "";
	const session: CookieSettings = {
		name: `${prefix}${SESSION_COOKIE}`,
		sameSite: options.sameSite ?? "lax",
		secure,
		maxAgeSeconds: sessionMaximumAgeSeconds,
	};
	const deviceCookie: CookieSettings = {
		name: `${prefix}${DEVICE_COOKIE}`,
		sameSite: "lax",
		secure,
		maxAgeSeconds: DEVICE_MAXIMUM_AGE_SECONDS,
	};

	const knownDevice = async (request: Request): Promise<string | undefined> => {
		const sealed = readCookie(request, deviceCookie.name);

		if (sealed === undefined) {
			return undefined;
		}

		const opened = await auth.sealer.unseal(sealed, DEVICE_PURPOSE);
		const id = opened.ok ? opened.value.id : undefined;

		return id !== undefined && DEVICE_ID.test(id) ? id : undefined;
	};

	const mode: Mode = {
		guard: (request) =>
			checkOrigin(request, origins).ok
				? undefined
				: answer(403, { error: "forbidden" }),
		preflight: () => undefined,
		decorate: (_request, response) => response,
		tokenOf: (request) => readCookie(request, session.name),
		async deviceFor(request): Promise<DeviceChoice> {
			const known = await knownDevice(request);

			if (known !== undefined) {
				return { device: known, cookies: [] };
			}

			const id = randomHex(DEVICE_ID_BYTES);
			const sealed = await auth.sealer.seal({
				purpose: DEVICE_PURPOSE,
				payload: { id },
				timeToLive: deviceLife.value,
			});

			return { device: id, cookies: [serializeCookie(deviceCookie, sealed)] };
		},
		signedIn: (signedIn, choice) =>
			answer(
				200,
				{
					subject: signedIn.subject,
					tenant: signedIn.tenant,
					identity: signedIn.identity,
					email: signedIn.email,
				},
				[serializeCookie(session, signedIn.token), ...choice.cookies],
			),
		sessionEnded: () => [clearCookie(session)],
	};

	return createHandler({ ...options, auth }, mode);
}
