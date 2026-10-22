import {
	createAuthClient,
	isUnavailableError,
	type UnavailableReason,
} from "@vow-auth/service";
import fastCheck from "fast-check";
import { expect, test, vi } from "vitest";
import { BASE_URL, claimsFactor, SERVICE_TOKEN } from "./support.js";

type FetchStub = (
	input: URL | RequestInfo,
	init?: RequestInit,
) => Promise<Response>;

const clientWith = (
	stub: FetchStub,
	reasons: UnavailableReason[] = [],
	timeoutMilliseconds = 5_000,
) => {
	return createAuthClient({
		baseUrl: BASE_URL,
		serviceToken: SERVICE_TOKEN,
		timeoutMilliseconds,
		fetch: stub,
		onUnavailable: (reason) => {
			reasons.push(reason);
		},
	});
};

const answering = (status: number, body: string): FetchStub => {
	return async () => new Response(body, { status });
};

const claims = {
	provider: "email",
	externalId: "a@example.com",
	email: "a@example.com",
	emailVerified: true,
};
const scope = { tenant: "acme", actor: "alice", resource: "email-link" };
const rule = { limit: 1, windowMilliseconds: 1_000 };

const everyOperation = async (client: ReturnType<typeof clientWith>) => {
	const refusals = [
		await client.signIn({
			tenant: "acme",
			device: "laptop",
			factor: claimsFactor,
			response: claims,
		}),
		await client.sessions.verify("token"),
		await client.meter.consume(scope, rule),
		await client.mutateIdentity("acme", "subject", { type: "delete" }),
	];
	const thrown = [];

	for (const call of [
		() => client.sessions.revoke({ tenant: "acme", scope: "tenant" }),
		() => client.meter.observe(scope, rule),
	]) {
		try {
			await call();
			thrown.push(false);
		} catch (error) {
			thrown.push(isUnavailableError(error));
		}
	}

	return { refusals, thrown };
};

const failures: readonly (readonly [string, FetchStub, UnavailableReason])[] = [
	[
		"a refused connection",
		async () => {
			throw new TypeError("fetch failed");
		},
		"network",
	],
	["a 500", answering(500, "oops"), "server-error"],
	["a 503", answering(503, ""), "server-error"],
	["a rejected secret", answering(401, "{}"), "unauthorized"],
	["a forbidden secret", answering(403, "{}"), "unauthorized"],
	["a redirect", answering(302, ""), "unexpected-status"],
	["an unknown route", answering(404, "<html>"), "unexpected-status"],
	["a body that is not JSON", answering(200, "<html>ok</html>"), "malformed"],
	["an empty body", answering(200, ""), "malformed"],
	["an empty object", answering(200, "{}"), "malformed"],
	["a success without a value", answering(200, '{"ok":true}'), "malformed"],
	["a failure without an error", answering(200, '{"ok":false}'), "malformed"],
	[
		"a failure with an error that is not a code",
		answering(200, '{"ok":false,"error":123}'),
		"malformed",
	],
	[
		"a success of the wrong kind",
		answering(200, '{"ok":true,"value":{"tenant":1}}'),
		"malformed",
	],
];

test.each(failures)(
	"A28: %s gives a refusal everywhere and never a success",
	async (_name, stub, reason) => {
		const reasons: UnavailableReason[] = [];
		const { refusals, thrown } = await everyOperation(
			clientWith(stub, reasons),
		);

		expect(refusals.every((result) => !result.ok)).toBe(true);
		expect(refusals[0]).toEqual({ ok: false, error: "unavailable" });
		expect(refusals[1]).toEqual({ ok: false, error: "unavailable" });
		expect(refusals[2]).toEqual({ ok: false, error: { code: "unavailable" } });
		expect(refusals[3]).toEqual({ ok: false, error: "unavailable" });
		expect(thrown[1]).toBe(true);

		if (!_name.startsWith("a success")) {
			expect(thrown[0]).toBe(true);
		}

		expect(new Set(reasons)).toContain(reason);
	},
);

test("A28: a call that outlasts the timeout is refused", async () => {
	const reasons: UnavailableReason[] = [];
	const hanging: FetchStub = (_input, init) => {
		return new Promise((_resolve, reject) => {
			init?.signal?.addEventListener("abort", () =>
				reject(init.signal?.reason),
			);
		});
	};
	const { refusals, thrown } = await everyOperation(
		clientWith(hanging, reasons, 30),
	);

	expect(refusals.every((result) => !result.ok)).toBe(true);
	expect(thrown).toEqual([true, true]);
	expect(new Set(reasons)).toEqual(new Set(["timeout"]));
});

test("A28: nothing is retried and a refusal is not cached", async () => {
	const stub = vi.fn<FetchStub>(answering(503, ""));
	const client = clientWith(stub);

	await client.sessions.verify("token");
	await client.sessions.verify("token");

	expect(stub).toHaveBeenCalledTimes(2);
});

test("a call sends the secret, forbids redirects and caching, and carries a timeout", async () => {
	const stub = vi.fn<FetchStub>(answering(200, '{"ok":false,"error":"x"}'));

	await clientWith(stub).sessions.verify("token");

	const [url, init] = stub.mock.calls[0] ?? [];

	expect(String(url)).toBe("http://auth.test/v1/sessions/verify");
	expect(init).toMatchObject({
		method: "POST",
		redirect: "error",
		cache: "no-store",
		body: JSON.stringify({ token: "token" }),
	});
	expect(init?.signal).toBeInstanceOf(AbortSignal);
	expect(new Headers(init?.headers).get("authorization")).toBe(
		`Bearer ${SERVICE_TOKEN}`,
	);
});

test("A28: a success needs a well formed answer, whatever else the service says", async () => {
	const isValidSession = (body: unknown): boolean => {
		if (typeof body !== "object" || body === null || Array.isArray(body)) {
			return false;
		}

		const value = Reflect.get(body, "value");

		return (
			Reflect.get(body, "ok") === true &&
			typeof value === "object" &&
			value !== null &&
			["tenant", "subject", "device", "session"].every(
				(key) => typeof Reflect.get(value, key) === "string",
			)
		);
	};

	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.oneof(
				fastCheck.jsonValue(),
				fastCheck.record({
					ok: fastCheck.boolean(),
					value: fastCheck.jsonValue(),
					error: fastCheck.jsonValue(),
				}),
				fastCheck.record({
					ok: fastCheck.constant(true),
					value: fastCheck.record({
						tenant: fastCheck.string(),
						subject: fastCheck.oneof(fastCheck.string(), fastCheck.integer()),
						device: fastCheck.string(),
						session: fastCheck.string(),
					}),
				}),
			),
			async (body) => {
				const result = await clientWith(
					answering(200, JSON.stringify(body)),
				).sessions.verify("token");

				expect(result.ok).toBe(isValidSession(body));
			},
		),
		{ numRuns: 400 },
	);
});

test("a throwing onUnavailable never changes the outcome", async () => {
	const client = createAuthClient({
		baseUrl: BASE_URL,
		serviceToken: SERVICE_TOKEN,
		timeoutMilliseconds: 1_000,
		fetch: answering(500, ""),
		onUnavailable: () => {
			throw new Error("the logger is down");
		},
	});

	expect(await client.sessions.verify("token")).toEqual({
		ok: false,
		error: "unavailable",
	});
});

test("confirming an email cannot travel, and is refused without a call", async () => {
	const stub = vi.fn<FetchStub>(answering(200, '{"ok":true}'));
	const result = await clientWith(stub).mutateIdentity("acme", "subject", {
		type: "confirm-email",
		proof: {},
	});

	expect(result).toEqual({ ok: false, error: "invalid-request" });
	expect(stub).not.toHaveBeenCalled();
});

test("a client needs a timeout it can use", () => {
	for (const timeoutMilliseconds of [0, -1, Number.NaN]) {
		expect(() =>
			createAuthClient({
				baseUrl: BASE_URL,
				serviceToken: SERVICE_TOKEN,
				timeoutMilliseconds,
			}),
		).toThrow(RangeError);
	}
});
