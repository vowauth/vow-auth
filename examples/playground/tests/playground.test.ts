import { expect, test } from "vitest";
import { createPlayground } from "../src/app.js";

const call = async (
	playground: Awaited<ReturnType<typeof createPlayground>>,
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

const stateOf = async (
	playground: Awaited<ReturnType<typeof createPlayground>>,
) => {
	await playground.runWorker();

	return (await call(playground, "/api/state")).data;
};

test("the page is served", async () => {
	const playground = await createPlayground();
	const response = await playground.handle(new Request("http://localhost/"));

	expect(response.status).toBe(200);
	expect(await response.text()).toContain("Vow Auth playground");
});

test("an email link signs in, the audit shows each step, revocation ends the session", async () => {
	const playground = await createPlayground();

	expect(
		(
			await call(playground, "/api/challenge", {
				tenant: "acme",
				email: "Alice@Example.com",
			})
		).status,
	).toBe(200);

	const afterChallenge = await stateOf(playground);
	const token = afterChallenge.mails[0].token;

	const signedIn = await call(playground, "/api/sign-in/email-link", {
		tenant: "acme",
		device: "laptop",
		token,
	});

	expect(signedIn.status).toBe(200);
	expect(signedIn.data.identity).toBe("created");

	expect(
		(await call(playground, "/api/me", {}, signedIn.data.token)).status,
	).toBe(200);

	expect(
		(
			await call(playground, "/api/sign-in/email-link", {
				tenant: "acme",
				device: "laptop",
				token,
			})
		).status,
	).toBe(401);

	await call(playground, "/api/revoke", { scope: "user" }, signedIn.data.token);

	expect(
		(await call(playground, "/api/me", {}, signedIn.data.token)).status,
	).toBe(401);

	const state = await stateOf(playground);
	const facts = state.audit.map(
		(entry: { event: string; outcome: string; reason: string }) =>
			`${entry.event}:${entry.outcome}:${entry.reason}`,
	);

	for (const expected of [
		"app.challenge:success:sent",
		"token.issue:success:issued",
		"token.consume:success:consumed",
		"proof.verify:success:verified",
		"identity.resolve:success:created",
		"policy.evaluate:success:allow",
		"session.issue:success:issued",
		"proof.verify:refusal:factor-rejected",
		"token.consume:refusal:not-found",
		"session.revoke:success:revoked",
		"session.verify:refusal:revoked",
	]) {
		expect(facts, expected).toContain(expected);
	}
});

test("an unverified provider claim does not take over an existing account", async () => {
	const playground = await createPlayground();

	await call(playground, "/api/challenge", {
		tenant: "acme",
		email: "victim@example.com",
	});
	const token = (await stateOf(playground)).mails[0].token;
	const victim = await call(playground, "/api/sign-in/email-link", {
		tenant: "acme",
		device: "laptop",
		token,
	});

	const attacker = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims: JSON.stringify({
			provider: "evil",
			externalId: "e-1",
			email: "victim@example.com",
			emailVerified: false,
		}),
	});

	expect(attacker.status).toBe(200);
	expect(attacker.data.identity).toBe("created");
	expect(attacker.data.subject).not.toBe(victim.data.subject);

	const verified = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims: JSON.stringify({
			provider: "google",
			externalId: "g-1",
			email: "victim@example.com",
			emailVerified: true,
		}),
	});

	expect(verified.data.identity).toBe("linked");
	expect(verified.data.subject).toBe(victim.data.subject);
});

test("malformed claims and banned subjects get no session", async () => {
	const playground = await createPlayground();

	const malicious = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims:
			'{"provider":"p","externalId":"e","emailVerified":false,"__proto__":{"emailVerified":true}}',
	});

	expect(malicious.status).toBe(401);

	const allowed = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims: JSON.stringify({
			provider: "p",
			externalId: "e",
			emailVerified: false,
		}),
	});

	await call(playground, "/api/ban", {
		subject: allowed.data.subject,
		banned: true,
	});

	const banned = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims: JSON.stringify({
			provider: "p",
			externalId: "e",
			emailVerified: false,
		}),
	});

	expect(banned.status).toBe(403);
});

test("confirming an email evicts the earlier claim and its session, and a delete ends every session", async () => {
	const playground = await createPlayground();
	const squatter = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims: JSON.stringify({
			provider: "evil",
			externalId: "e-1",
			email: "victim@example.com",
			emailVerified: false,
		}),
	});

	await call(playground, "/api/challenge", {
		tenant: "acme",
		email: "victim@example.com",
	});
	const token = (await stateOf(playground)).mails[0].token;
	const victim = await call(playground, "/api/sign-in/email-link", {
		tenant: "acme",
		device: "laptop",
		token,
	});

	expect(
		(await call(playground, "/api/me", {}, squatter.data.token)).status,
	).toBe(401);
	expect(
		(await call(playground, "/api/me", {}, victim.data.token)).status,
	).toBe(200);

	await call(playground, "/api/delete-subject", {
		subject: victim.data.subject,
	});

	expect(
		(await call(playground, "/api/me", {}, victim.data.token)).status,
	).toBe(401);

	const facts = (await stateOf(playground)).audit.map(
		(entry: { event: string; reason: string }) =>
			`${entry.event}:${entry.reason}`,
	);

	expect(facts).toContain("identity.mutate:email-confirmed");
	expect(facts).toContain("identity.mutate:deleted");
});

test("sending links to one address is limited, however it is spelled", async () => {
	const playground = await createPlayground();
	const statuses = [];

	for (const email of [
		"alice@example.com",
		"ALICE@Example.com",
		" alice@example.com ",
		"alice@example.com",
	]) {
		statuses.push(
			(await call(playground, "/api/challenge", { tenant: "acme", email }))
				.status,
		);
	}

	const other = await call(playground, "/api/challenge", {
		tenant: "acme",
		email: "bob@example.com",
	});

	expect(statuses).toEqual([200, 200, 200, 429]);
	expect(other.status).toBe(200);

	const facts = (await stateOf(playground)).audit.map(
		(entry: { event: string; reason: string }) =>
			`${entry.event}:${entry.reason}`,
	);

	expect(facts).toContain("meter.consume:limit-exceeded");
});

test("revoking one device leaves the other signed in", async () => {
	const playground = await createPlayground();
	const claims = JSON.stringify({
		provider: "p",
		externalId: "e",
		emailVerified: false,
	});
	const laptop = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "laptop",
		claims,
	});
	const phone = await call(playground, "/api/sign-in/provider", {
		tenant: "acme",
		device: "phone",
		claims,
	});

	await call(playground, "/api/revoke", { scope: "device" }, laptop.data.token);

	expect(
		(await call(playground, "/api/me", {}, laptop.data.token)).status,
	).toBe(401);
	expect((await call(playground, "/api/me", {}, phone.data.token)).status).toBe(
		200,
	);
});
