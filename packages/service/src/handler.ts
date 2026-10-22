import {
	applyLimit,
	assertLimit,
	defineDuration,
	defineMeterRule,
	ERROR_CODES,
	type Factor,
	fail,
	type Limit,
	type MeterRule,
	type MeterScope,
	type RevocationLevel,
} from "@vow-auth/core";
import { SERVICE_ROUTES, type ServiceSurface } from "./protocol.js";
import {
	field,
	hasOnlyKeys,
	isFiniteNumber,
	isRecord,
	isString,
} from "./shared.js";

/** Options for creating the service handler. */
export type AuthHandlerOptions = {
	readonly auth: ServiceSurface;
	/** The factors the service can run, by id. A client names one by id; the code never travels. */
	readonly factors: Readonly<Record<string, Factor>>;
	/** The secrets callers present as `Authorization: Bearer`. Several allow rotation; each is at least 32 characters. */
	readonly serviceTokens: readonly string[];
	/** The largest request body in bytes; a larger one is refused with 413. */
	readonly maximumBodyBytes: number;
	/**
	 * How often a sign in may be tried through the service. The answer is
	 * required: a limiter made with `createLimiter`, whose scopes can use the
	 * request and the tenant, or `"off"` when the caller limits it already. A
	 * refused sign in answers `{ ok: false, error: "rate-limited" }`.
	 */
	readonly signInLimit: Limit<{
		readonly request: Request;
		readonly tenant: string;
	}>;
};

/** Answers one request of the service. */
export type AuthHandler = (request: Request) => Promise<Response>;

const MINIMUM_TOKEN_LENGTH = 32;

const encoder = new TextEncoder();

const digestOf = async (text: string): Promise<Uint8Array> => {
	return new Uint8Array(
		await crypto.subtle.digest("SHA-256", encoder.encode(text)),
	);
};

const sameDigest = (first: Uint8Array, second: Uint8Array): boolean => {
	let difference = first.length ^ second.length;

	for (let index = 0; index < first.length; index += 1) {
		difference |= (first[index] ?? 0) ^ (second[index] ?? 0);
	}

	return difference === 0;
};

const BASE_HEADERS = { "cache-control": "no-store" };

const respond = (status: number, body: unknown): Response => {
	return new Response(JSON.stringify(body), {
		status,
		headers: { ...BASE_HEADERS, "content-type": "application/json" },
	});
};

const problem = (
	status: number,
	title: string,
	headers: Readonly<Record<string, string>> = {},
): Response => {
	return new Response(JSON.stringify({ type: "about:blank", title, status }), {
		status,
		headers: {
			...BASE_HEADERS,
			...headers,
			"content-type": "application/problem+json",
		},
	});
};

const readLimited = async (
	request: Request,
	limit: number,
): Promise<string | "too-large" | "malformed"> => {
	const declared = Number(request.headers.get("content-length"));

	if (Number.isFinite(declared) && declared > limit) {
		return "too-large";
	}

	const reader = request.body?.getReader();

	if (reader === undefined) {
		return "";
	}

	const chunks: Uint8Array[] = [];
	let total = 0;

	for (;;) {
		const chunk = await reader.read();

		if (chunk.done) {
			break;
		}

		total += chunk.value.byteLength;

		if (total > limit) {
			await reader.cancel();

			return "too-large";
		}

		chunks.push(chunk.value);
	}

	const body = new Uint8Array(total);
	let offset = 0;

	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}

	try {
		return new TextDecoder("utf-8", { fatal: true }).decode(body);
	} catch {
		return "malformed";
	}
};

const parseScope = (raw: unknown): MeterScope | undefined => {
	if (!isRecord(raw) || !hasOnlyKeys(raw, ["tenant", "actor", "resource"])) {
		return undefined;
	}

	const tenant = field(raw, "tenant");
	const actor = field(raw, "actor");
	const resource = field(raw, "resource");

	return isString(tenant) && isString(actor) && isString(resource)
		? { tenant, actor, resource }
		: undefined;
};

const parseRule = (raw: unknown): MeterRule | undefined => {
	if (!isRecord(raw) || !hasOnlyKeys(raw, ["limit", "windowMilliseconds"])) {
		return undefined;
	}

	const limit = field(raw, "limit");
	const windowMilliseconds = field(raw, "windowMilliseconds");

	if (!isFiniteNumber(limit) || !isFiniteNumber(windowMilliseconds)) {
		return undefined;
	}

	const defined = defineMeterRule({ limit, windowMilliseconds });

	return defined.ok ? defined.value : undefined;
};

const parseLevel = (raw: unknown): RevocationLevel | undefined => {
	if (!isRecord(raw) || !hasOnlyKeys(raw, ["tenant", "scope", "id"])) {
		return undefined;
	}

	const tenant = field(raw, "tenant");
	const scope = field(raw, "scope");
	const id = field(raw, "id");

	if (!isString(tenant)) {
		return undefined;
	}

	if (scope === "tenant") {
		return id === undefined ? { tenant, scope } : undefined;
	}

	if (
		(scope === "user" ||
			scope === "device" ||
			scope === "session" ||
			scope === "agent" ||
			scope === "delegation") &&
		isString(id)
	) {
		return { tenant, scope, id };
	}

	return undefined;
};

/**
 * Creates the Fetch API handler of the service: a thin layer over the same
 * `Auth` functions that run in process. Every request must carry a service
 * secret, checked in constant time before anything else, so an unauthenticated
 * caller cannot even learn which routes exist. A refusal of the domain, such as
 * an invalid session or a refused sign in, is an ordinary answer, `200` with
 * `{ ok: false, error }`, like an inactive token in RFC 7662; errors of the
 * protocol are `application/problem+json` (RFC 9457) without internals. Every
 * answer is `Cache-Control: no-store`, because it can carry a token.
 */
export function createAuthHandler(options: AuthHandlerOptions): AuthHandler {
	const { auth, factors, serviceTokens, maximumBodyBytes, signInLimit } =
		options;

	assertLimit("signInLimit", signInLimit);

	if (
		serviceTokens.length === 0 ||
		serviceTokens.some((token) => token.length < MINIMUM_TOKEN_LENGTH)
	) {
		throw new RangeError(
			`serviceTokens must hold at least one secret, each at least ${MINIMUM_TOKEN_LENGTH} characters`,
		);
	}

	if (!Number.isSafeInteger(maximumBodyBytes) || maximumBodyBytes <= 0) {
		throw new RangeError("maximumBodyBytes must be a positive integer");
	}

	const expectedDigests = Promise.all(serviceTokens.map(digestOf));

	const isAuthorized = async (request: Request): Promise<boolean> => {
		const header = request.headers.get("authorization") ?? "";
		const presented = header.startsWith("Bearer ")
			? header.slice("Bearer ".length)
			: "";
		const presentedDigest = await digestOf(presented);
		let matched = false;

		for (const expected of await expectedDigests) {
			matched = sameDigest(presentedDigest, expected) || matched;
		}

		return matched;
	};

	const routes = new Map<
		string,
		(
			body: Record<string, unknown>,
			request: Request,
		) => Promise<Response | undefined>
	>([
		[
			SERVICE_ROUTES.signIn,
			async (body, request) => {
				const tenant = field(body, "tenant");
				const device = field(body, "device");
				const factorId = field(body, "factor");
				const continuation = field(body, "continuation");

				if (
					!hasOnlyKeys(body, [
						"tenant",
						"device",
						"factor",
						"response",
						"continuation",
					]) ||
					!isString(tenant) ||
					!isString(device) ||
					!isString(factorId) ||
					(continuation !== undefined && !isString(continuation))
				) {
					return undefined;
				}

				const factor = Object.hasOwn(factors, factorId)
					? factors[factorId]
					: undefined;
				const allowed = await applyLimit(signInLimit, { request, tenant });

				if (!allowed.ok) {
					return respond(200, fail(allowed.error.code));
				}

				return respond(
					200,
					factor === undefined
						? fail(ERROR_CODES.invalidRequest)
						: await auth.signIn({
								tenant,
								device,
								factor,
								response: field(body, "response"),
								...(continuation === undefined ? {} : { continuation }),
							}),
				);
			},
		],
		[
			SERVICE_ROUTES.verifySession,
			async (body) => {
				const token = field(body, "token");

				return hasOnlyKeys(body, ["token"]) && isString(token)
					? respond(200, await auth.sessions.verify(token))
					: undefined;
			},
		],
		[
			SERVICE_ROUTES.delegateAgent,
			async (body) => {
				const sessionToken = field(body, "sessionToken");
				const agent = field(body, "agent");
				const timeToLiveMilliseconds = field(body, "timeToLiveMilliseconds");
				const boundToSession = field(body, "boundToSession");
				const timeToLive = isFiniteNumber(timeToLiveMilliseconds)
					? defineDuration(timeToLiveMilliseconds)
					: undefined;

				if (
					!hasOnlyKeys(body, [
						"sessionToken",
						"agent",
						"timeToLiveMilliseconds",
						"boundToSession",
					]) ||
					!isString(sessionToken) ||
					!isString(agent) ||
					timeToLive === undefined ||
					!timeToLive.ok ||
					(boundToSession !== undefined && typeof boundToSession !== "boolean")
				) {
					return undefined;
				}

				return respond(
					200,
					await auth.agents.delegate(sessionToken, {
						agent,
						timeToLive: timeToLive.value,
						...(boundToSession === undefined ? {} : { boundToSession }),
					}),
				);
			},
		],
		[
			SERVICE_ROUTES.verifyAgent,
			async (body) => {
				const token = field(body, "token");

				return hasOnlyKeys(body, ["token"]) && isString(token)
					? respond(200, await auth.agents.verify(token))
					: undefined;
			},
		],
		[
			SERVICE_ROUTES.revokeSession,
			async (body) => {
				const level = parseLevel(field(body, "level"));

				if (!hasOnlyKeys(body, ["level"]) || level === undefined) {
					return undefined;
				}

				await auth.sessions.revoke(level);

				return respond(200, { ok: true });
			},
		],
		[
			SERVICE_ROUTES.meterConsume,
			async (body) => {
				const scope = parseScope(field(body, "scope"));
				const rule = parseRule(field(body, "rule"));
				const cost = field(body, "cost");

				if (
					!hasOnlyKeys(body, ["scope", "rule", "cost"]) ||
					scope === undefined ||
					rule === undefined ||
					(cost !== undefined && !isFiniteNumber(cost))
				) {
					return undefined;
				}

				return respond(200, await auth.meter.consume(scope, rule, cost));
			},
		],
		[
			SERVICE_ROUTES.meterObserve,
			async (body) => {
				const scope = parseScope(field(body, "scope"));
				const rule = parseRule(field(body, "rule"));
				const cost = field(body, "cost");

				if (
					!hasOnlyKeys(body, ["scope", "rule", "cost"]) ||
					scope === undefined ||
					rule === undefined ||
					(cost !== undefined && !isFiniteNumber(cost))
				) {
					return undefined;
				}

				return respond(200, await auth.meter.observe(scope, rule, cost));
			},
		],
		[
			SERVICE_ROUTES.deleteIdentity,
			async (body) => {
				const tenant = field(body, "tenant");
				const subject = field(body, "subject");

				return hasOnlyKeys(body, ["tenant", "subject"]) &&
					isString(tenant) &&
					isString(subject)
					? respond(
							200,
							await auth.mutateIdentity(tenant, subject, { type: "delete" }),
						)
					: undefined;
			},
		],
	]);

	return async (request) => {
		if (!(await isAuthorized(request))) {
			return problem(401, "Unauthorized", { "www-authenticate": "Bearer" });
		}

		const route = routes.get(new URL(request.url).pathname);

		if (route === undefined) {
			return problem(404, "Not Found");
		}

		if (request.method !== "POST") {
			return problem(405, "Method Not Allowed", { allow: "POST" });
		}

		const text = await readLimited(request, maximumBodyBytes);

		if (text === "too-large") {
			return problem(413, "Content Too Large");
		}

		let body: unknown;

		try {
			body = text === "malformed" ? undefined : JSON.parse(text);
		} catch {
			body = undefined;
		}

		if (!isRecord(body)) {
			return problem(400, "Bad Request");
		}

		try {
			return (await route(body, request)) ?? problem(400, "Bad Request");
		} catch {
			return problem(500, "Internal Server Error");
		}
	};
}
