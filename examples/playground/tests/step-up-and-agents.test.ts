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

const claims = (email: string) =>
	JSON.stringify({
		provider: "google",
		externalId: `g-${email}`,
		email,
		emailVerified: true,
	});

const signIn = async (
	playground: Playground,
	email: string,
	device = "laptop",
) => {
	const result = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device,
		claims: claims(email),
	});

	if (result.status !== 200) {
		throw new Error(`the sign in must pass, got ${result.status}`);
	}

	return result.data;
};

const enableSecondFactor = async (playground: Playground, token: string) => {
	const result = await call(
		playground,
		"/api/second-factor/enable",
		{ enabled: true },
		token,
	);

	expect(result.status).toBe(200);

	return result.data;
};

test("a person with a second factor is asked for it, and the session records both", async () => {
	const playground = await createPlayground();
	const first = await signIn(playground, "alice@example.com");
	const factor = await enableSecondFactor(playground, first.token);
	const challenge = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims: claims("alice@example.com"),
	});

	expect(challenge.status).toBe(401);
	expect(challenge.data).toMatchObject({
		error: "step-up-required",
		factor: "authenticator",
		continuation: expect.any(String),
	});

	const done = await call(playground, "/api/sign-in/second-factor", {
		tenant: "acme",
		device: "phone",
		account: factor.account,
		code: factor.code,
		continuation: challenge.data.continuation,
	});

	expect(done.status).toBe(200);

	const me = await call(playground, "/api/me", {}, done.data.token);

	expect(me.data.methods).toEqual(["simulated-provider", "authenticator"]);

	const state = await stateOf(playground);
	const reasons = state.audit.map(
		(entry: { event: string; reason: string }) =>
			`${entry.event}:${entry.reason}`,
	);

	expect(reasons).toContain("policy.evaluate:step-up");
});

test("a wrong code burns the continuation and a code for another account is refused", async () => {
	const playground = await createPlayground();
	const alice = await signIn(playground, "alice@example.com");
	const factor = await enableSecondFactor(playground, alice.token);
	const bob = await signIn(playground, "bob@example.com");
	const bobFactor = await enableSecondFactor(playground, bob.token);
	const step = async (email: string) =>
		(
			await call(playground, "/api/sign-in/provider", {
				tenant: "acme",
				device: "phone",
				claims: claims(email),
			})
		).data.continuation;
	const second = (continuation: string, account: string, code: string) =>
		call(playground, "/api/sign-in/second-factor", {
			tenant: "acme",
			device: "phone",
			account,
			code,
			continuation,
		});

	const continuation = await step("alice@example.com");

	expect(
		(await second(continuation, factor.account, "000000")).data.error,
	).toBe("invalid-proof");
	expect(
		(await second(continuation, factor.account, factor.code)).data.error,
	).toBe("invalid-token");

	const crossed = await step("alice@example.com");

	expect(
		(await second(crossed, bobFactor.account, bobFactor.code)).data.error,
	).toBe("invalid-proof");
});

test("a sensitive action can demand a recent sign in or a second factor", async () => {
	const playground = await createPlayground();
	const signedIn = await signIn(playground, "alice@example.com");

	expect(
		(
			await call(
				playground,
				"/api/sensitive",
				{ maxAgeSeconds: 60 },
				signedIn.token,
			)
		).status,
	).toBe(200);
	expect(
		(
			await call(
				playground,
				"/api/sensitive",
				{ maxAgeSeconds: -1 },
				signedIn.token,
			)
		).data.error,
	).toBe("recent-sign-in-required");
	expect(
		(
			await call(
				playground,
				"/api/sensitive",
				{ requireMethod: "authenticator" },
				signedIn.token,
			)
		).data,
	).toMatchObject({ error: "step-up-required", needs: "authenticator" });
});

const delegate = async (
	playground: Playground,
	token: string,
	agent: string,
	options: { boundToSession?: boolean; canWrite?: boolean } = {},
) => {
	const result = await call(
		playground,
		"/api/agents/delegate",
		{ agent, ...options },
		token,
	);

	expect(result.status).toBe(200);

	return result.data;
};

test("an agent acts for a person with the rights the application gave it, and is never a person", async () => {
	const playground = await createPlayground();
	const alice = await signIn(playground, "alice@example.com");
	const reader = await delegate(playground, alice.token, "reader-bot");
	const writer = await delegate(playground, alice.token, "writer-bot", {
		canWrite: true,
	});

	expect(
		(
			await call(
				playground,
				"/api/agents/act",
				{ action: "read" },
				reader.token,
			)
		).data,
	).toMatchObject({
		actingAs: "agent",
		agent: "reader-bot",
		forPerson: alice.subject,
	});
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
	expect(
		(
			await call(
				playground,
				"/api/agents/act",
				{ action: "write", text: "hello" },
				writer.token,
			)
		).data.notes,
	).toEqual(["writer-bot: hello"]);
	expect((await call(playground, "/api/me", {}, reader.token)).status).toBe(
		401,
	);
	expect(
		(await call(playground, "/api/notes", { action: "read" }, reader.token))
			.status,
	).toBe(401);
	expect(
		(await call(playground, "/api/agents/act", { action: "read" }, alice.token))
			.status,
	).toBe(401);
});

test("revoking a level ends exactly the agents below it", async () => {
	const playground = await createPlayground();
	const alice = await signIn(playground, "alice@example.com", "laptop");
	const bob = await signIn(playground, "bob@example.com", "laptop");
	const unbound = await delegate(playground, alice.token, "mcp-1");
	const bound = await delegate(playground, alice.token, "mcp-1", {
		boundToSession: true,
	});
	const other = await delegate(playground, alice.token, "mcp-2");
	const bobs = await delegate(playground, bob.token, "mcp-1");
	const alive = async () => {
		const state = await stateOf(playground);

		return state.agents
			.filter((agent: { alive: boolean }) => agent.alive)
			.map((agent: { delegation: string }) => agent.delegation)
			.sort();
	};

	expect(await alive()).toEqual(
		[
			unbound.delegation,
			bound.delegation,
			other.delegation,
			bobs.delegation,
		].sort(),
	);

	await call(
		playground,
		"/api/revoke",
		{ scope: "delegation", id: unbound.delegation },
		alice.token,
	);
	expect(await alive()).not.toContain(unbound.delegation);
	expect(await alive()).toContain(bound.delegation);

	await call(playground, "/api/revoke", { scope: "session" }, alice.token);

	const fresh = await signIn(playground, "alice@example.com", "phone");

	expect(await alive()).not.toContain(bound.delegation);
	expect(await alive()).toContain(other.delegation);

	await call(
		playground,
		"/api/revoke",
		{ scope: "agent", id: "mcp-1" },
		fresh.token,
	);
	expect(await alive()).toEqual([other.delegation]);

	await call(playground, "/api/revoke", { scope: "user" }, fresh.token);
	expect(await alive()).toEqual([]);
});
