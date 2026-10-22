import { expect, test } from "vitest";
import { createPlayground } from "../src/app.js";

type Playground = Awaited<ReturnType<typeof createPlayground>>;

const call = async (
	playground: Playground,
	path: string,
	body?: unknown,
	token?: string,
) => {
	const headers = new Headers({ "content-type": "application/json" });

	if (token !== undefined) {
		headers.set("authorization", `Bearer ${token}`);
	}

	const response = await playground.handle(
		new Request(`http://localhost${path}`, {
			method: body === undefined && path === "/api/state" ? "GET" : "POST",
			headers,
			body: body === undefined ? null : JSON.stringify(body),
		}),
	);

	return { status: response.status, data: await response.json() };
};

const stateOf = async (playground: Playground) => {
	await playground.runWorker();

	return (await call(playground, "/api/state")).data;
};

const claimsFor = (externalId: string) =>
	JSON.stringify({ provider: "idp", externalId, emailVerified: false });

test("in observe mode the limit refuses nothing, says what it would have done, and leaves the other settings alone", async () => {
	const playground = await createPlayground();

	await call(playground, "/api/settings", { mailProviderDown: true });
	await call(playground, "/api/settings", { rateLimitMode: "observe" });

	expect((await stateOf(playground)).settings).toEqual({
		mailProviderDown: true,
		rateLimitMode: "observe",
	});

	const answers = [];

	for (let request = 0; request < 5; request += 1) {
		answers.push(
			await call(playground, "/api/challenge", {
				tenant: "acme",
				email: "alice@example.com",
			}),
		);
	}

	expect(answers.map((answer) => answer.status)).toEqual([
		200, 200, 200, 200, 200,
	]);
	expect(answers.map((answer) => answer.data.observed.wouldRefuse)).toEqual([
		false,
		false,
		false,
		true,
		true,
	]);

	const state = await stateOf(playground);

	expect(
		state.audit.filter(
			(entry: { event: string; outcome: string }) =>
				entry.event === "meter.consume" && entry.outcome === "observation",
		),
	).toHaveLength(2);

	await call(playground, "/api/settings", { rateLimitMode: "enforce" });

	expect(
		(
			await call(playground, "/api/challenge", {
				tenant: "acme",
				email: "alice@example.com",
			})
		).status,
	).toBe(429);
});

test("a rule or a cost the meter cannot count is a refusal, never an error", async () => {
	const playground = await createPlayground();

	for (const body of [
		{ limit: 0 },
		{ limit: 1.5 },
		{ windowMilliseconds: -1 },
	]) {
		expect((await call(playground, "/api/probe/meter", body)).data).toEqual({
			defined: false,
			error: "invalid-request",
		});
	}

	for (const cost of [0, -1, 1.5, 99]) {
		expect((await call(playground, "/api/probe/meter", { cost })).data).toEqual(
			{
				defined: true,
				ok: false,
				error: { code: "invalid-request" },
			},
		);
	}

	expect(
		(await call(playground, "/api/probe/meter", { cost: 1 })).data,
	).toMatchObject({
		defined: true,
		ok: true,
		used: 1,
	});
});

test("names no store can keep stop at the border, and ordinary Unicode is welcome", async () => {
	const playground = await createPlayground();
	const nul = String.fromCharCode(0);
	const lone = String.fromCharCode(0xd800);
	const attempts = [
		{
			tenant: `acme${nul}`,
			device: "laptop",
			claims: claimsFor("a"),
			error: "invalid-request",
		},
		{
			tenant: "acme",
			device: `lap${nul}top`,
			claims: claimsFor("a"),
			error: "invalid-request",
		},
		{
			tenant: "acme",
			device: "laptop",
			claims: claimsFor(`a${nul}b`),
			error: "invalid-proof",
		},
		{
			tenant: "acme",
			device: "laptop",
			claims: claimsFor(`a${lone}b`),
			error: "invalid-proof",
		},
	];

	for (const { error, ...body } of attempts) {
		const result = await call(playground, "/api/sign-in/provider", body);

		expect(result.data.error, JSON.stringify(body)).toBe(error);
	}

	expect(
		(
			await call(playground, "/api/sign-in/provider", {
				tenant: "acme",
				device: "Ivan's 👩‍💻 laptop",
				claims: claimsFor("ivan"),
			})
		).status,
	).toBe(200);

	const state = await stateOf(playground);

	expect(state.subjects).toHaveLength(1);
});

test("a redirect goes only to a path of this site or to an origin on the list", async () => {
	const playground = await createPlayground();
	const verdict = async (target: unknown) =>
		(await call(playground, "/api/probe/redirect", { target })).data.ok;
	const good = [
		"/dashboard",
		"http://localhost:3000/after",
		"https://app.example.com/home?x=1",
	];
	const bad = [
		"//evil.com",
		"/\\evil.com",
		"https://evil.com/",
		"https://app.example.com@evil.com/",
		"https://app.example.com.evil.com/",
		"http://app.example.com/",
		"javascript:alert(1)",
		"https://user:pw@app.example.com/",
		"/‮/evil",
		"",
		42,
	];

	for (const target of good) {
		expect(await verdict(target), String(target)).toBe(true);
	}

	for (const target of bad) {
		expect(await verdict(target), String(target)).toBe(false);
	}
});

test("a call goes only to a listed name whose addresses are all public", async () => {
	const playground = await createPlayground();
	const verdict = async (url: string) =>
		(await call(playground, "/api/probe/outbound", { url })).data;

	expect(await verdict("https://hooks.example.com/in")).toMatchObject({
		ok: true,
		redirect: "error",
	});

	for (const url of [
		"http://hooks.example.com/in",
		"https://hooks.example.com:8443/in",
		"https://127.0.0.1/",
		"https://169.254.169.254/latest/meta-data/",
		"https://sub.hooks.example.com/",
		"https://rebind.example.com/in",
		"https://user:pw@hooks.example.com/",
		"https://hooks.example.com@evil.com/",
	]) {
		expect((await verdict(url)).ok, url).toBe(false);
	}
});

test("what an agent may do is decided by an ability narrowed from the person's, and every verdict is audited", async () => {
	const playground = await createPlayground();
	const signedIn = (
		await call(playground, "/api/sign-in/provider", {
			tenant: "acme",
			device: "laptop",
			claims: claimsFor("alice"),
		})
	).data;
	const reader = (
		await call(
			playground,
			"/api/agents/delegate",
			{ agent: "reader" },
			signedIn.token,
		)
	).data;

	await call(
		playground,
		"/api/notes",
		{ action: "write", text: "mine" },
		signedIn.token,
	);
	await call(playground, "/api/agents/act", { action: "read" }, reader.token);
	expect(
		(
			await call(
				playground,
				"/api/agents/act",
				{ action: "write", text: "x" },
				reader.token,
			)
		).status,
	).toBe(403);

	const verdicts = (await stateOf(playground)).audit
		.filter((entry: { event: string }) => entry.event === "authorize.check")
		.map(
			(entry: { reason: string; detail: string }) =>
				`${entry.reason}:${entry.detail}`,
		)
		.reverse();

	expect(verdicts).toEqual([
		"allowed:action=write, resource=note",
		"allowed:action=read, resource=note",
		"forbidden:action=write, resource=note",
	]);
});
