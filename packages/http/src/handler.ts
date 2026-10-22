import {
	type Auth,
	applyLimit,
	assertLimit,
	type Factor,
	type Limit,
	type MeterRefusal,
	type Result,
	type RevocationLevel,
	type SignedIn,
	type SignInRefusal,
} from "@vow-auth/core";

/** What a limit is asked about: the request, which route it is, the tenant and the body. */
export type LimitInput = {
	readonly request: Request;
	readonly route: "sign-in" | "challenge";
	readonly tenant: string;
	readonly body: Readonly<Record<string, unknown>>;
};

/** Sends a challenge of a factor, such as a link to an address, from the body of a request. */
export type Challenge = (
	body: Readonly<Record<string, unknown>>,
) => Promise<Result<unknown, string | MeterRefusal>>;

/** Options that both handlers share. */
export type HandlerOptions = {
	readonly auth: Pick<Auth, "signIn" | "sessions">;
	/** The factors a person can sign in with, by id: the id is the last part of `/sign-in/<id>`. */
	readonly factors: Readonly<Record<string, Factor>>;
	/** The factors that start with a challenge, by id: the last part of `/challenge/<id>`. */
	readonly challenges?: Readonly<Record<string, Challenge>>;
	/** The tenant of a request: a fixed one, or one chosen by the host or path. */
	readonly tenant: string | ((request: Request) => string | undefined);
	/** Where the routes are mounted, such as `/auth`. Empty when they are at the root. */
	readonly basePath?: string;
	/** The largest request body in bytes; a larger one is refused with 413. */
	readonly maximumBodyBytes: number;
	/**
	 * How often a sign in or a challenge may be tried. The answer is required:
	 * a limiter made with `createLimiter`, or `"off"` when something in front
	 * of the handler limits it already.
	 */
	readonly limit: Limit<LimitInput>;
};

/** How a sign in reaches the caller: a cookie of the browser, or a token in the body. */
export type DeviceChoice = {
	readonly device: string;
	/** `Set-Cookie` headers that go with the answer, such as the cookie of a new device. */
	readonly cookies: readonly string[];
};

/** What makes a handler a cookie handler or a bearer handler. */
export type Mode = {
	/** Refuses a request before it is read, or lets it through. */
	readonly guard: (request: Request) => Response | undefined;
	/** Answers a preflight of the browser, when the mode takes calls from other origins. */
	readonly preflight: (request: Request) => Response | undefined;
	/** Adds what the mode puts on every answer, such as CORS headers. */
	readonly decorate: (request: Request, response: Response) => Response;
	readonly tokenOf: (request: Request) => string | undefined;
	readonly deviceFor: (
		request: Request,
		body: Readonly<Record<string, unknown>>,
	) => Promise<DeviceChoice | undefined>;
	readonly signedIn: (signedIn: SignedIn, choice: DeviceChoice) => Response;
	/** `Set-Cookie` headers that end a session in the browser. */
	readonly sessionEnded: () => readonly string[];
};

const JSON_TYPE = /^application\/json(\s*;.*)?$/i;

const STATUS_OF_CODE: Readonly<Record<string, number>> = {
	"invalid-request": 400,
	"invalid-proof": 401,
	"invalid-token": 401,
	"no-proof": 401,
	"invalid-session": 401,
	"no-allow": 403,
	forbidden: 403,
	"rate-limited": 429,
	unavailable: 503,
};
const DEFAULT_REFUSAL_STATUS = 422;

const ROUTES: readonly {
	readonly pattern: RegExp;
	readonly method: "GET" | "POST";
}[] = [
	{ pattern: /^\/sign-in\/([^/]+)$/, method: "POST" },
	{ pattern: /^\/challenge\/([^/]+)$/, method: "POST" },
	{ pattern: /^\/session$/, method: "GET" },
	{ pattern: /^\/sign-out$/, method: "POST" },
	{ pattern: /^\/sign-out\/device$/, method: "POST" },
	{ pattern: /^\/sign-out\/everywhere$/, method: "POST" },
];

/** Builds the JSON answer every route gives: never cached, never sniffed. */
export const answer = (
	status: number,
	body: unknown,
	cookies: readonly string[] = [],
	headers: Readonly<Record<string, string>> = {},
): Response => {
	const response = Response.json(body, {
		status,
		headers: {
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
			...headers,
		},
	});

	for (const cookie of cookies) {
		response.headers.append("set-cookie", cookie);
	}

	return response;
};

const refusalAnswer = (
	code: string,
	resetsAtMilliseconds?: number,
): Response => {
	const status = STATUS_OF_CODE[code] ?? DEFAULT_REFUSAL_STATUS;

	return answer(
		status,
		{ error: code },
		[],
		status === 429 && resetsAtMilliseconds !== undefined
			? {
					"retry-after": String(
						Math.max(1, Math.ceil((resetsAtMilliseconds - Date.now()) / 1_000)),
					),
				}
			: {},
	);
};

const readBody = async (
	request: Request,
	maximumBytes: number,
): Promise<
	| { readonly kind: "body"; readonly body: Record<string, unknown> }
	| { readonly kind: "refused"; readonly status: number }
> => {
	if (!JSON_TYPE.test(request.headers.get("content-type") ?? "")) {
		return { kind: "refused", status: 415 };
	}

	const declared = Number(request.headers.get("content-length"));

	if (Number.isFinite(declared) && declared > maximumBytes) {
		return { kind: "refused", status: 413 };
	}

	const chunks: Uint8Array[] = [];
	let total = 0;

	const reader = request.body?.getReader();

	while (reader !== undefined) {
		const { done, value } = await reader.read();

		if (done) {
			break;
		}

		total += value.byteLength;

		if (total > maximumBytes) {
			await reader.cancel();

			return { kind: "refused", status: 413 };
		}

		chunks.push(value);
	}

	const joined = new Uint8Array(total);
	let offset = 0;

	for (const chunk of chunks) {
		joined.set(chunk, offset);
		offset += chunk.byteLength;
	}

	try {
		const parsed: unknown = JSON.parse(
			new TextDecoder("utf-8", { fatal: true }).decode(joined),
		);

		return typeof parsed === "object" &&
			parsed !== null &&
			!Array.isArray(parsed)
			? { kind: "body", body: Object.fromEntries(Object.entries(parsed)) }
			: { kind: "refused", status: 400 };
	} catch {
		return { kind: "refused", status: 400 };
	}
};

const PROBLEMS: Readonly<Record<number, string>> = {
	400: "bad-request",
	404: "not-found",
	405: "method-not-allowed",
	413: "payload-too-large",
	415: "unsupported-media-type",
};

const problem = (status: number): Response => {
	return answer(status, { error: PROBLEMS[status] ?? "bad-request" });
};

const decoded = (part: string): string => {
	try {
		return decodeURIComponent(part);
	} catch {
		return part;
	}
};

/**
 * Builds the handler both modes share. The mode decides how a person proves
 * who they are to each request; the routes, the limit, the checks of the body
 * and the answers are the same.
 */
export function createHandler(
	options: HandlerOptions,
	mode: Mode,
): (request: Request) => Promise<Response> {
	const { auth, factors, challenges = {}, maximumBodyBytes, limit } = options;
	const basePath = options.basePath ?? "";
	const fixedTenant = options.tenant;
	const tenantOf =
		typeof fixedTenant === "string" ? () => fixedTenant : fixedTenant;

	assertLimit("limit", limit);

	if (!Number.isSafeInteger(maximumBodyBytes) || maximumBodyBytes <= 0) {
		throw new RangeError("maximumBodyBytes must be a positive integer");
	}

	if (basePath !== "" && !/^\/[^/?#]+(\/[^/?#]+)*$/.test(basePath)) {
		throw new RangeError("basePath must be empty or a path like /auth");
	}

	const verified = async (request: Request) => {
		const token = mode.tokenOf(request);

		return token === undefined ? undefined : auth.sessions.verify(token);
	};

	const revoke = async (
		request: Request,
		levelOf: (session: {
			tenant: string;
			subject: string;
			device: string;
			session: string;
		}) => RevocationLevel,
	): Promise<Response> => {
		const current = await verified(request);

		if (current?.ok) {
			await auth.sessions.revoke(levelOf(current.value));
		}

		return answer(200, { ok: true }, mode.sessionEnded());
	};

	const signIn = async (
		request: Request,
		factorId: string,
		body: Readonly<Record<string, unknown>>,
	): Promise<Response> => {
		const tenant = tenantOf(request);
		const factor = Object.hasOwn(factors, factorId)
			? factors[factorId]
			: undefined;

		if (tenant === undefined || factor === undefined) {
			return refusalAnswer("invalid-request");
		}

		const allowed = await applyLimit(limit, {
			request,
			route: "sign-in",
			tenant,
			body,
		});

		if (!allowed.ok) {
			return refusalAnswer(
				allowed.error.code,
				"resetsAtMilliseconds" in allowed.error
					? allowed.error.resetsAtMilliseconds
					: undefined,
			);
		}

		const choice = await mode.deviceFor(request, body);

		if (choice === undefined) {
			return refusalAnswer("invalid-request");
		}

		const continuation = body.continuation;
		const result = await auth.signIn({
			tenant,
			device: choice.device,
			factor,
			response: body.response,
			...(typeof continuation === "string" ? { continuation } : {}),
		});

		if (result.ok) {
			return mode.signedIn(result.value, choice);
		}

		return signInRefusal(result.error, choice.cookies);
	};

	const challenge = async (
		request: Request,
		factorId: string,
		body: Readonly<Record<string, unknown>>,
	): Promise<Response> => {
		const tenant = tenantOf(request);
		const send = Object.hasOwn(challenges, factorId)
			? challenges[factorId]
			: undefined;

		if (tenant === undefined || send === undefined) {
			return refusalAnswer("invalid-request");
		}

		const allowed = await applyLimit(limit, {
			request,
			route: "challenge",
			tenant,
			body,
		});

		if (!allowed.ok) {
			return refusalAnswer(
				allowed.error.code,
				"resetsAtMilliseconds" in allowed.error
					? allowed.error.resetsAtMilliseconds
					: undefined,
			);
		}

		const sent = await send(body);

		if (sent.ok) {
			return answer(200, { ok: true });
		}

		return typeof sent.error === "string"
			? refusalAnswer(sent.error)
			: refusalAnswer(
					sent.error.code,
					"resetsAtMilliseconds" in sent.error
						? sent.error.resetsAtMilliseconds
						: undefined,
				);
	};

	const signInRefusal = (
		error: SignInRefusal,
		cookies: readonly string[],
	): Response => {
		if (typeof error === "string") {
			const refused = refusalAnswer(error);

			for (const cookie of cookies) {
				refused.headers.append("set-cookie", cookie);
			}

			return refused;
		}

		return answer(
			401,
			{
				error: error.code,
				factor: error.factor,
				continuation: error.continuation,
			},
			cookies,
		);
	};

	const route = async (request: Request): Promise<Response> => {
		const path = new URL(request.url).pathname;

		if (basePath !== "" && !path.startsWith(`${basePath}/`)) {
			return problem(404);
		}

		const local = basePath === "" ? path : path.slice(basePath.length);
		const matched = ROUTES.map((candidate) => ({
			candidate,
			match: candidate.pattern.exec(local),
		})).find((entry) => entry.match !== null);

		if (matched === undefined) {
			return problem(404);
		}

		if (request.method === "OPTIONS") {
			return mode.preflight(request) ?? problem(405);
		}

		if (request.method !== matched.candidate.method) {
			return answer(405, { error: "method-not-allowed" }, [], {
				allow: matched.candidate.method,
			});
		}

		const target = decoded(matched.match?.[1] ?? "");

		if (matched.candidate.method === "GET") {
			const current = await verified(request);

			return current?.ok
				? answer(200, current.value)
				: answer(401, { error: "invalid-session" }, mode.sessionEnded());
		}

		const refused = mode.guard(request);

		if (refused !== undefined) {
			return refused;
		}

		const read = await readBody(request, maximumBodyBytes);

		if (read.kind === "refused") {
			return problem(read.status);
		}

		if (local.startsWith("/sign-in/")) {
			return signIn(request, target, read.body);
		}

		if (local.startsWith("/challenge/")) {
			return challenge(request, target, read.body);
		}

		if (local === "/sign-out") {
			return revoke(request, (session) => ({
				tenant: session.tenant,
				scope: "session",
				id: session.session,
			}));
		}

		return local === "/sign-out/device"
			? revoke(request, (session) => ({
					tenant: session.tenant,
					scope: "device",
					id: session.device,
				}))
			: revoke(request, (session) => ({
					tenant: session.tenant,
					scope: "user",
					id: session.subject,
				}));
	};

	return async (request) => {
		try {
			return mode.decorate(request, await route(request));
		} catch {
			return mode.decorate(request, answer(500, { error: "internal" }));
		}
	};
}
