import { createAuthHandler } from "@vow-auth/service";
import { expect, test } from "vitest";
import {
	BASE_URL,
	claimsFactor,
	createCore,
	createHandler,
	SERVICE_TOKEN,
} from "./support.js";

const post = (
	path: string,
	body: unknown,
	headers: Record<string, string> = {},
): Request => {
	return new Request(`${BASE_URL}${path}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${SERVICE_TOKEN}`,
			"content-type": "application/json",
			...headers,
		},
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
};

const problemOf = async (response: Response) => {
	expect(response.headers.get("content-type")).toBe("application/problem+json");

	const body: unknown = await response.json();

	expect(body).toEqual({
		type: "about:blank",
		title: expect.any(String),
		status: response.status,
	});

	return body;
};

test("a request without a valid secret is refused before anything else, with no hint of the routes", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);
	const wrong = [
		undefined,
		"",
		"Bearer",
		"Bearer ",
		`Bearer ${SERVICE_TOKEN.slice(0, -1)}`,
		`Bearer ${SERVICE_TOKEN}x`,
		`bearer ${SERVICE_TOKEN}`,
		`Basic ${SERVICE_TOKEN}`,
		SERVICE_TOKEN,
	];

	for (const authorization of wrong) {
		for (const path of ["/v1/sessions/verify", "/nothing"]) {
			const response = await handler(
				new Request(`${BASE_URL}${path}`, {
					method: "POST",
					headers: authorization === undefined ? {} : { authorization },
					body: "{}",
				}),
			);

			expect(response.status, `${authorization} ${path}`).toBe(401);
			expect(response.headers.get("www-authenticate")).toBe("Bearer");
			await problemOf(response);
		}
	}
});

test("every secret of the list works, so a secret can be rotated", async () => {
	const { auth } = createCore();
	const rotating = createAuthHandler({
		auth,
		factors: {},
		serviceTokens: [SERVICE_TOKEN, `${SERVICE_TOKEN}-next`],
		maximumBodyBytes: 1_000,
	});

	for (const token of [SERVICE_TOKEN, `${SERVICE_TOKEN}-next`]) {
		const response = await rotating(
			post(
				"/v1/sessions/verify",
				{ token: "x" },
				{ authorization: `Bearer ${token}` },
			),
		);

		expect(response.status).toBe(200);
	}
});

test("a refusal of the domain is an ordinary answer, not an error of the protocol", async () => {
	const { auth } = createCore();
	const response = await createHandler(auth)(
		post("/v1/sessions/verify", { token: "1.garbage" }),
	);

	expect(response.status).toBe(200);
	expect(response.headers.get("content-type")).toBe("application/json");
	expect(await response.json()).toEqual({
		ok: false,
		error: "invalid-session",
	});
});

test("every answer forbids caching, because it can carry a token", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);
	const responses = [
		await handler(post("/v1/sessions/verify", { token: "x" })),
		await handler(post("/v1/sessions/verify", "not json")),
		await handler(post("/nothing", {})),
		await handler(
			new Request(`${BASE_URL}/v1/sessions/verify`, {
				method: "GET",
				headers: { authorization: `Bearer ${SERVICE_TOKEN}` },
			}),
		),
		await handler(
			new Request(`${BASE_URL}/v1/sessions/verify`, { method: "POST" }),
		),
	];

	for (const response of responses) {
		expect(response.headers.get("cache-control")).toBe("no-store");
	}
});

test("a route that does not exist is 404 and a method other than POST is 405", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);
	const missing = await handler(post("/v1/nothing", {}));
	const wrongMethod = await handler(
		new Request(`${BASE_URL}/v1/sessions/verify`, {
			method: "GET",
			headers: { authorization: `Bearer ${SERVICE_TOKEN}` },
		}),
	);

	expect(missing.status).toBe(404);
	await problemOf(missing);
	expect(wrongMethod.status).toBe(405);
	expect(wrongMethod.headers.get("allow")).toBe("POST");
	await problemOf(wrongMethod);
});

test("a body that is too large is refused, declared or streamed", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);
	const big = JSON.stringify({ token: "x".repeat(20_000) });
	const declared = await handler(post("/v1/sessions/verify", big));
	const streamed = await handler(
		new Request(`${BASE_URL}/v1/sessions/verify`, {
			method: "POST",
			headers: { authorization: `Bearer ${SERVICE_TOKEN}` },
			body: new ReadableStream({
				start(controller) {
					controller.enqueue(new TextEncoder().encode(big));
					controller.close();
				},
			}),
			duplex: "half",
		} as RequestInit),
	);

	expect(declared.status).toBe(413);
	expect(streamed.status).toBe(413);
	await problemOf(declared);
});

test("a body that is not a JSON object is 400", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);

	for (const body of ["", "not json", "[]", '"text"', "null", "42", "{"]) {
		const response = await handler(post("/v1/sessions/verify", body));

		expect(response.status, body).toBe(400);
		await problemOf(response);
	}

	const invalidUtf8 = await handler(
		new Request(`${BASE_URL}/v1/sessions/verify`, {
			method: "POST",
			headers: { authorization: `Bearer ${SERVICE_TOKEN}` },
			body: new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]),
		}),
	);

	expect(invalidUtf8.status).toBe(400);
});

test("a body of the wrong shape, with an unknown key or a prototype key, is 400", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);
	const bad: readonly (readonly [string, unknown])[] = [
		["/v1/sessions/verify", {}],
		["/v1/sessions/verify", { token: 1 }],
		["/v1/sessions/verify", { token: "x", extra: true }],
		[
			"/v1/sessions/verify",
			JSON.parse('{"token":"x","__proto__":{"admin":true}}'),
		],
		["/v1/sign-in", { tenant: "a", device: "d" }],
		["/v1/agents/verify", {}],
		["/v1/agents/verify", { token: 1 }],
		["/v1/agents/verify", { token: "x", extra: true }],
		["/v1/agents/delegate", { sessionToken: "x", agent: "a" }],
		[
			"/v1/agents/delegate",
			{ sessionToken: "x", agent: "a", timeToLiveMilliseconds: 0 },
		],
		[
			"/v1/agents/delegate",
			{ sessionToken: "x", agent: 1, timeToLiveMilliseconds: 1000 },
		],
		[
			"/v1/agents/delegate",
			{
				sessionToken: "x",
				agent: "a",
				timeToLiveMilliseconds: 1000,
				boundToSession: "yes",
			},
		],
		[
			"/v1/agents/delegate",
			{
				sessionToken: "x",
				agent: "a",
				timeToLiveMilliseconds: 1000,
				extra: true,
			},
		],
		[
			"/v1/sign-in",
			{
				tenant: "a",
				device: "d",
				factor: "claims",
				response: {},
				continuation: 5,
			},
		],
		["/v1/sign-in", { tenant: "a", device: "d", factor: 1, response: 1 }],
		[
			"/v1/sessions/revoke",
			{ level: { tenant: "a", scope: "tenant", id: "x" } },
		],
		["/v1/sessions/revoke", { level: { tenant: "a", scope: "user" } }],
		[
			"/v1/sessions/revoke",
			{ level: { tenant: "a", scope: "robot", id: "x" } },
		],
		["/v1/sessions/revoke", { level: "tenant" }],
		["/v1/meter/consume", { scope: { tenant: "a" }, rule: {} }],
		[
			"/v1/meter/consume",
			{
				scope: { tenant: "a", actor: "b", resource: "c" },
				rule: { limit: "1", windowMilliseconds: 1 },
			},
		],
		["/v1/identities/delete", { tenant: "a" }],
	];

	for (const [path, body] of bad) {
		const response = await handler(post(path, body));

		expect(response.status, `${path} ${JSON.stringify(body)}`).toBe(400);
	}
});

test("A26: a rule the core cannot count is 400, a cost it cannot count is an ordinary refusal", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);
	const scope = { tenant: "a", actor: "b", resource: "c" };

	for (const route of ["/v1/meter/consume", "/v1/meter/observe"]) {
		for (const rule of [
			{ limit: 0, windowMilliseconds: 1_000 },
			{ limit: 1, windowMilliseconds: 1.5 },
		]) {
			const response = await handler(post(route, { scope, rule }));

			expect(response.status, `${route} ${JSON.stringify(rule)}`).toBe(400);
		}

		for (const cost of [5, 0]) {
			const response = await handler(
				post(route, {
					scope,
					rule: { limit: 1, windowMilliseconds: 1_000 },
					cost,
				}),
			);

			expect(response.status).toBe(200);
			expect(await response.json()).toEqual({
				ok: false,
				error: { code: "invalid-request" },
			});
		}
	}
});

test("a factor is named by id; an unknown id, or a name from the prototype, is a refusal", async () => {
	const { auth } = createCore();
	const handler = createHandler(auth);

	for (const factor of [
		"unknown",
		"constructor",
		"__proto__",
		"toString",
		"",
	]) {
		const response = await handler(
			post("/v1/sign-in", {
				tenant: "acme",
				device: "d",
				factor,
				response: {},
			}),
		);

		expect(response.status, factor).toBe(200);
		expect(await response.json(), factor).toEqual({
			ok: false,
			error: "invalid-request",
		});
	}
});

test("an unexpected failure is a 500 that says nothing about its cause", async () => {
	const { auth } = createCore();
	const failing = createAuthHandler({
		auth: {
			...auth,
			sessions: {
				verify: async () => {
					throw new Error("the secret database password is hunter2");
				},
				revoke: async () => undefined,
			},
		},
		factors: { [claimsFactor.id]: claimsFactor },
		serviceTokens: [SERVICE_TOKEN],
		maximumBodyBytes: 1_000,
	});
	const response = await failing(post("/v1/sessions/verify", { token: "x" }));
	const text = await response.text();

	expect(response.status).toBe(500);
	expect(text).not.toContain("hunter2");
	expect(response.headers.get("content-type")).toBe("application/problem+json");
});

test("a handler needs secrets it can use and a body limit", () => {
	const { auth } = createCore();
	const base = {
		auth,
		factors: {},
		serviceTokens: [SERVICE_TOKEN],
		maximumBodyBytes: 1_000,
	};

	for (const broken of [
		{ serviceTokens: [] },
		{ serviceTokens: ["short"] },
		{ serviceTokens: [SERVICE_TOKEN, "short"] },
		{ maximumBodyBytes: 0 },
		{ maximumBodyBytes: 1.5 },
		{ maximumBodyBytes: Number.NaN },
	]) {
		expect(() => createAuthHandler({ ...base, ...broken })).toThrow(RangeError);
	}
});
