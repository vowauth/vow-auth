import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	type Auth,
	createAuth,
	type Factor,
	requireFactor,
	succeed,
} from "@vow-auth/core";
import { createLimiter, createMeter } from "@vow-auth/core/internal";
import {
	createBearerHandler,
	createCookieHandler,
	type LimitInput,
} from "@vow-auth/http";
import { meterRuleOf } from "@vow-auth/test-support";
import { expect, test } from "vitest";

const ORIGIN = "https://app.example.com";
const TENANT = "acme";
const SESSION_COOKIE = "__Host-vow-session";
const DEVICE_COOKIE = "__Host-vow-device";
const SECONDS_PER_HOUR = 3_600;

const claimsFactor: Factor = {
	id: "claims",
	strength: "possession",
	verify: async (response) => succeed(response),
};

const totpFactor: Factor = {
	id: "totp",
	strength: "possession",
	verify: async (response) => succeed(response),
};

const claims = (email: string) => ({
	provider: "email",
	externalId: email,
	email,
	emailVerified: true,
});

const createCore = (stepUpSubjects = new Set<string>()) => {
	const meterStore = createMemoryMeterStore({ maximumBytes: 1_000_000 });
	const auth: Auth = createAuth({
		identities: createMemoryIdentityStore(),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore,
		secrets: [{ version: 1, value: "http-seal-0123456789abcdefghijklmnop" }],
		maximumLifeTimeMilliseconds: 3_600_000,
		sessionTimeToLiveMilliseconds: 3_600_000,
		stepUpTimeToLiveMilliseconds: 300_000,
		policy: ({ subject, proofs }) =>
			stepUpSubjects.has(subject) &&
			!proofs.some((proof) => proof.factor === totpFactor.id)
				? requireFactor(totpFactor.id)
				: "allow",
		audit: async () => undefined,
	});

	return { auth, meterStore };
};

const shared = {
	factors: { claims: claimsFactor, totp: totpFactor },
	tenant: TENANT,
	basePath: "/auth",
	maximumBodyBytes: 4_096,
	limit: "off",
} as const;

const createCookie = (overrides: Record<string, unknown> = {}) => {
	const { auth } = createCore();

	return createCookieHandler({
		...shared,
		auth,
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
		...overrides,
	});
};

const createBearer = (overrides: Record<string, unknown> = {}) => {
	const { auth } = createCore();

	return createBearerHandler({
		...shared,
		auth,
		allowedOrigins: ["https://spa.example.com"],
		...overrides,
	});
};

const post = (
	path: string,
	body: unknown,
	headers: Record<string, string> = {},
) =>
	new Request(`${ORIGIN}/auth${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			origin: ORIGIN,
			"sec-fetch-site": "same-origin",
			...headers,
		},
		body: JSON.stringify(body),
	});

const get = (path: string, headers: Record<string, string> = {}) =>
	new Request(`${ORIGIN}/auth${path}`, { headers });

const cookiesOf = (response: Response): Record<string, string> =>
	Object.fromEntries(
		response.headers.getSetCookie().map((line) => {
			const [pair = ""] = line.split(";");
			const separator = pair.indexOf("=");

			return [pair.slice(0, separator), pair.slice(separator + 1)];
		}),
	);

const cookieHeader = (response: Response): string =>
	Object.entries(cookiesOf(response))
		.filter(([, value]) => value !== "")
		.map(([name, value]) => `${name}=${value}`)
		.join("; ");

const signInBody = (email: string) => ({ response: claims(email) });

test("a browser signs in and gets a cookie, never the token in the body", async () => {
	const handle = createCookie();
	const response = await handle(
		post("/sign-in/claims", signInBody("a@x.test")),
	);
	const body = await response.json();

	expect(response.status).toBe(200);
	expect(body).toMatchObject({ tenant: TENANT, email: "a@x.test" });
	expect(Object.keys(body)).not.toContain("token");
	expect(JSON.stringify(body)).not.toContain(
		cookiesOf(response)[SESSION_COOKIE],
	);

	const [session, device] = response.headers
		.getSetCookie()
		.map((line) => line.split("; "));

	expect(session).toEqual(
		expect.arrayContaining(["Secure", "HttpOnly", "Path=/", "SameSite=Lax"]),
	);
	expect(session?.some((part) => part.startsWith("Domain"))).toBe(false);
	expect(device?.[0]?.startsWith(`${DEVICE_COOKIE}=`)).toBe(true);
	expect(response.headers.get("cache-control")).toBe("no-store");
});

test("the cookie opens the session, and reading it changes nothing", async () => {
	const handle = createCookie();
	const signedIn = await handle(
		post("/sign-in/claims", signInBody("a@x.test")),
	);
	const current = await handle(
		get("/session", { cookie: cookieHeader(signedIn) }),
	);

	expect(current.status).toBe(200);
	expect(await current.json()).toMatchObject({ tenant: TENANT });
	expect(current.headers.getSetCookie()).toEqual([]);
});

test("a cookie that is not valid is refused and cleared", async () => {
	const handle = createCookie();
	const response = await handle(
		get("/session", { cookie: `${SESSION_COOKIE}=forged` }),
	);

	expect(response.status).toBe(401);
	expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");
});

test("a browser handler ignores the header Authorization", async () => {
	const { auth } = createCore();
	const cookie = createCookieHandler({
		...shared,
		auth,
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	});
	const bearer = createBearerHandler({ ...shared, auth, allowedOrigins: [] });
	const signedIn = await bearer(
		post("/sign-in/claims", {
			...signInBody("a@x.test"),
			device: "d".repeat(32),
		}),
	);
	const { token } = await signedIn.json();
	const headers = { authorization: `Bearer ${token}` };

	expect((await bearer(get("/session", headers))).status).toBe(200);
	expect((await cookie(get("/session", headers))).status).toBe(401);
});

test("a bearer handler returns the token, sets no cookie and reads none", async () => {
	const { auth } = createCore();
	const cookie = createCookieHandler({
		...shared,
		auth,
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	});
	const bearer = createBearerHandler({ ...shared, auth, allowedOrigins: [] });

	const signedIn = await bearer(
		post("/sign-in/claims", {
			...signInBody("a@x.test"),
			device: "d".repeat(32),
		}),
	);
	const body = await signedIn.json();

	expect(signedIn.status).toBe(200);
	expect(typeof body.token).toBe("string");
	expect(signedIn.headers.getSetCookie()).toEqual([]);

	const viaCookie = await bearer(
		get("/session", { cookie: `${SESSION_COOKIE}=${body.token}` }),
	);

	expect(viaCookie.status).toBe(401);
	expect(viaCookie.headers.getSetCookie()).toEqual([]);

	const fromBrowser = await cookie(
		get("/session", { cookie: `${SESSION_COOKIE}=${body.token}` }),
	);

	expect(fromBrowser.status).toBe(200);
});

test("a bearer sign in needs a device of its own, long enough to be unique", async () => {
	const handle = createBearer();

	for (const device of [undefined, "phone", 7, "x".repeat(15)]) {
		const response = await handle(
			post("/sign-in/claims", { ...signInBody("a@x.test"), device }),
		);

		expect(response.status, String(device)).toBe(400);
	}
});

test("another site cannot post to a browser handler", async () => {
	const handle = createCookie();
	const attempts: Record<string, string>[] = [
		{ origin: "https://evil.example", "sec-fetch-site": "cross-site" },
		{ origin: "null", "sec-fetch-site": "cross-site" },
		{ origin: "https://app.example.com.evil.example" },
		{ origin: "", "sec-fetch-site": "" },
	];

	for (const headers of attempts) {
		const response = await handle(
			post("/sign-in/claims", signInBody("a@x.test"), headers),
		);

		expect(response.status, JSON.stringify(headers)).toBe(403);
		expect(response.headers.getSetCookie()).toEqual([]);
	}
});

test("a form post, or a body that is not JSON, is refused before it is read", async () => {
	const handle = createCookie();

	for (const contentType of [
		"application/x-www-form-urlencoded",
		"text/plain",
		"multipart/form-data; boundary=x",
	]) {
		const response = await handle(
			post("/sign-in/claims", signInBody("a@x.test"), {
				"content-type": contentType,
			}),
		);

		expect(response.status, contentType).toBe(415);
	}

	const broken = new Request(`${ORIGIN}/auth/sign-in/claims`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			origin: ORIGIN,
			"sec-fetch-site": "same-origin",
		},
		body: "{not json",
	});

	expect((await handle(broken)).status).toBe(400);

	for (const body of [[], "text", null, 7]) {
		expect(
			(await handle(post("/sign-in/claims", body))).status,
			JSON.stringify(body),
		).toBe(400);
	}
});

test("a body larger than the limit is refused whatever it declares", async () => {
	const handle = createCookie({ maximumBodyBytes: 64 });
	const large = post("/sign-in/claims", { padding: "x".repeat(200) });

	expect((await handle(large)).status).toBe(413);

	const streamed = new Request(`${ORIGIN}/auth/sign-in/claims`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			origin: ORIGIN,
			"sec-fetch-site": "same-origin",
			"content-length": "10",
		},
		body: JSON.stringify({ padding: "x".repeat(200) }),
	});

	expect((await handle(streamed)).status).toBe(413);
});

test("the routes are the routes: unknown paths and wrong methods are refused", async () => {
	const handle = createCookie();

	expect((await handle(get("/nothing"))).status).toBe(404);
	expect((await handle(new Request(`${ORIGIN}/session`))).status).toBe(404);
	expect((await handle(get("/sign-in/claims"))).status).toBe(405);
	expect((await handle(post("/session", {}))).status).toBe(405);
	expect((await handle(post("/sign-in/unknown", {}))).status).toBe(400);
	expect((await handle(post("/sign-in/constructor", {}))).status).toBe(400);
	expect((await handle(post("/sign-in/__proto__", {}))).status).toBe(400);
});

test("signing out ends this session, this device or the person, and clears the cookie", async () => {
	const { auth } = createCore();
	const handle = createCookieHandler({
		...shared,
		auth,
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	});

	const laptop = await handle(post("/sign-in/claims", signInBody("a@x.test")));
	const laptopCookie = cookieHeader(laptop);
	const phone = await handle(post("/sign-in/claims", signInBody("a@x.test")));
	const phoneCookie = cookieHeader(phone);
	const laptopAgain = await handle(
		post("/sign-in/claims", signInBody("a@x.test"), {
			cookie:
				laptopCookie
					.split("; ")
					.find((part) => part.startsWith(DEVICE_COOKIE)) ?? "",
		}),
	);
	const laptopAgainCookie = cookieHeader(laptopAgain);

	const alive = async (cookie: string) =>
		(await handle(get("/session", { cookie }))).status === 200;

	expect(await alive(laptopCookie)).toBe(true);
	expect(await alive(phoneCookie)).toBe(true);

	const out = await handle(post("/sign-out", {}, { cookie: laptopCookie }));

	expect(out.status).toBe(200);
	expect(out.headers.getSetCookie()[0]).toContain("Max-Age=0");
	expect(await alive(laptopCookie)).toBe(false);
	expect(await alive(laptopAgainCookie)).toBe(true);

	await handle(post("/sign-out/device", {}, { cookie: laptopAgainCookie }));

	expect(await alive(laptopAgainCookie)).toBe(false);
	expect(await alive(phoneCookie)).toBe(true);

	await handle(post("/sign-out/everywhere", {}, { cookie: phoneCookie }));

	expect(await alive(phoneCookie)).toBe(false);
});

test("signing out without a valid session still answers 200 and clears the cookie", async () => {
	const handle = createCookie();
	const out = await handle(post("/sign-out", {}));

	expect(out.status).toBe(200);
	expect(out.headers.getSetCookie()[0]).toContain("Max-Age=0");
});

test("a sealed device cookie that was altered is not trusted and a new device is made", async () => {
	const handle = createCookie();
	const first = await handle(post("/sign-in/claims", signInBody("a@x.test")));
	const device = cookiesOf(first)[DEVICE_COOKIE] ?? "";
	const altered = `${device.slice(0, -2)}${device.endsWith("AA") ? "BB" : "AA"}`;
	const second = await handle(
		post("/sign-in/claims", signInBody("a@x.test"), {
			cookie: `${DEVICE_COOKIE}=${altered}`,
		}),
	);

	expect(second.status).toBe(200);
	expect(cookiesOf(second)[DEVICE_COOKIE]).toBeDefined();
	expect(cookiesOf(second)[DEVICE_COOKIE]).not.toBe(altered);
});

test("a known device is kept, not renewed, on the next sign in", async () => {
	const handle = createCookie();
	const first = await handle(post("/sign-in/claims", signInBody("a@x.test")));
	const second = await handle(
		post("/sign-in/claims", signInBody("a@x.test"), {
			cookie: `${DEVICE_COOKIE}=${cookiesOf(first)[DEVICE_COOKIE]}`,
		}),
	);

	expect(cookiesOf(second)[DEVICE_COOKIE]).toBeUndefined();
	expect(cookiesOf(second)[SESSION_COOKIE]).toBeDefined();
});

test("Strict is a choice of the cookie of the session", async () => {
	const handle = createCookie({ sameSite: "strict" });
	const response = await handle(
		post("/sign-in/claims", signInBody("a@x.test")),
	);
	const [session, device] = response.headers.getSetCookie();

	expect(session).toContain("SameSite=Strict");
	expect(device).toContain("SameSite=Lax");
});

test("a page on http://localhost gets cookies without Secure and without the prefix", async () => {
	const { auth } = createCore();
	const handle = createCookieHandler({
		...shared,
		auth,
		origin: "http://localhost:3000",
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	});
	const response = await handle(
		new Request("http://localhost:3000/auth/sign-in/claims", {
			method: "POST",
			headers: {
				"content-type": "application/json",
				origin: "http://localhost:3000",
			},
			body: JSON.stringify(signInBody("a@x.test")),
		}),
	);
	const [session] = response.headers.getSetCookie();

	expect(session?.startsWith("vow-session=")).toBe(true);
	expect(session).not.toContain("Secure");
});

test("a step-up is asked for in the answer and finished with the continuation", async () => {
	const stepUpSubjects = new Set<string>();
	const { auth, meterStore } = createCore(stepUpSubjects);
	const handle = createCookieHandler({
		...shared,
		auth,
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	});

	expect(meterStore).toBeDefined();

	const first = await handle(post("/sign-in/claims", signInBody("a@x.test")));
	const { subject } = await first.json();

	stepUpSubjects.add(subject);

	const asked = await handle(post("/sign-in/claims", signInBody("a@x.test")));
	const body = await asked.json();

	expect(asked.status).toBe(401);
	expect(body).toMatchObject({ error: "step-up-required", factor: "totp" });
	expect(
		asked.headers
			.getSetCookie()
			.some((line) => line.startsWith(SESSION_COOKIE)),
	).toBe(false);

	const finished = await handle(
		post(
			"/sign-in/totp",
			{
				response: claims("a@x.test"),
				continuation: body.continuation,
			},
			{ cookie: cookieHeader(asked) },
		),
	);

	expect(finished.status).toBe(200);
	expect(cookiesOf(finished)[SESSION_COOKIE]).toBeDefined();
});

test("a limit refuses with 429 and when to come back, per scope", async () => {
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
	});
	const handle = createCookie({
		limit: createLimiter<LimitInput>({
			meter,
			rule: meterRuleOf({ limit: 2, windowMilliseconds: 60_000 }),
			scopes: ({ route, tenant, body }) => [
				{
					tenant,
					actor: String((body.response as { email?: unknown }).email),
					resource: `${route}:target`,
				},
			],
		}),
	});

	for (let attempt = 0; attempt < 2; attempt += 1) {
		expect(
			(await handle(post("/sign-in/claims", signInBody("a@x.test")))).status,
		).toBe(200);
	}

	const refused = await handle(post("/sign-in/claims", signInBody("a@x.test")));

	expect(refused.status).toBe(429);
	expect(await refused.json()).toEqual({ error: "rate-limited" });
	expect(Number(refused.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
	expect(refused.headers.getSetCookie()).toEqual([]);
	expect(
		(await handle(post("/sign-in/claims", signInBody("b@x.test")))).status,
	).toBe(200);
});

test("a limit that is forgotten stops the handler from being built", () => {
	const { auth } = createCore();
	const { limit: _limit, ...withoutLimit } = shared;

	for (const options of [
		withoutLimit,
		{ ...shared, limit: undefined },
		{ ...shared, limit: "none" },
	]) {
		expect(() =>
			createCookieHandler({
				...(options as typeof shared),
				auth,
				origin: ORIGIN,
				sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
			}),
		).toThrow(TypeError);
		expect(() =>
			createBearerHandler({
				...(options as typeof shared),
				auth,
				allowedOrigins: [],
			}),
		).toThrow(TypeError);
	}
});

test("a bearer handler answers a preflight only to the origins it lists", async () => {
	const handle = createBearer();
	const preflight = (origin: string) =>
		handle(
			new Request(`${ORIGIN}/auth/sign-in/claims`, {
				method: "OPTIONS",
				headers: {
					origin,
					"access-control-request-method": "POST",
					"access-control-request-headers": "authorization, content-type",
				},
			}),
		);

	const allowed = await preflight("https://spa.example.com");

	expect(allowed.status).toBe(204);
	expect(allowed.headers.get("access-control-allow-origin")).toBe(
		"https://spa.example.com",
	);
	expect(allowed.headers.get("access-control-allow-credentials")).toBeNull();
	expect(allowed.headers.get("vary")).toContain("origin");

	for (const origin of ["https://evil.example", "null", "*"]) {
		const refused = await preflight(origin);

		expect(refused.status, origin).toBe(403);
		expect(refused.headers.get("access-control-allow-origin")).toBeNull();
	}
});

test("a bearer answer carries the CORS headers of a listed origin only", async () => {
	const handle = createBearer();
	const answerTo = (origin: string) =>
		handle(
			post(
				"/sign-in/claims",
				{ ...signInBody("a@x.test"), device: "d".repeat(32) },
				{ origin },
			),
		);

	expect(
		(await answerTo("https://spa.example.com")).headers.get(
			"access-control-allow-origin",
		),
	).toBe("https://spa.example.com");
	expect(
		(await answerTo("https://evil.example")).headers.get(
			"access-control-allow-origin",
		),
	).toBeNull();
});

test("a browser handler answers no preflight: other sites get nothing", async () => {
	const handle = createCookie();
	const response = await handle(
		new Request(`${ORIGIN}/auth/sign-in/claims`, {
			method: "OPTIONS",
			headers: { origin: "https://evil.example" },
		}),
	);

	expect(response.status).toBe(405);
	expect(response.headers.get("access-control-allow-origin")).toBeNull();
});

test("the options of a handler are checked when it is built", () => {
	const { auth } = createCore();
	const base = {
		...shared,
		auth,
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	};

	for (const bad of [
		{ origin: "https://app.example.com/path" },
		{ origin: "app.example.com" },
		{ origin: "*" },
		{ allowedOrigins: ["https://*.example.com"] },
		{ sessionMaximumAgeSeconds: 0 },
		{ sessionMaximumAgeSeconds: 1.5 },
		{ maximumBodyBytes: 0 },
		{ basePath: "auth" },
		{ basePath: "/auth/" },
	]) {
		expect(
			() => createCookieHandler({ ...base, ...bad }),
			JSON.stringify(bad),
		).toThrow(RangeError);
	}
});

test("a failure inside a handler is a 500 that says nothing", async () => {
	const { auth } = createCore();
	const handle = createCookieHandler({
		...shared,
		auth: {
			...auth,
			signIn: async () => {
				throw new Error("secret detail");
			},
		},
		origin: ORIGIN,
		sessionMaximumAgeSeconds: SECONDS_PER_HOUR,
	});
	const response = await handle(
		post("/sign-in/claims", signInBody("a@x.test")),
	);

	expect(response.status).toBe(500);
	expect(await response.text()).not.toContain("secret");
});
