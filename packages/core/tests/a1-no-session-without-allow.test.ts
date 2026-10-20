import { evaluatePolicy, issueSession } from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

test("allow from evaluatePolicy yields a session", async () => {
	const result = issueSession(await evaluatePolicy("u1", () => "allow"));
	expect(result.ok && result.value.subject).toBe("u1");
});

test("any policy output other than exact 'allow' yields no session", async () => {
	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.anything(), async (verdict) => {
			fastCheck.pre(verdict !== "allow");
			expect(issueSession(await evaluatePolicy("u1", () => verdict)).ok).toBe(
				false,
			);
		}),
	);
});

test("a throwing policy yields no session", async () => {
	const decision = await evaluatePolicy("u1", () => {
		throw new Error("boom");
	});
	expect(issueSession(decision).ok).toBe(false);
});

test("forged decisions yield no session", async () => {
	fastCheck.assert(
		fastCheck.property(fastCheck.anything(), (forged) => {
			expect(issueSession(forged).ok).toBe(false);
		}),
	);
	expect(issueSession({ kind: "allow", subject: "attacker" }).ok).toBe(false);
	expect(
		issueSession(JSON.parse('{"kind":"allow","subject":"attacker"}')).ok,
	).toBe(false);
});

test("an issued allow decision cannot be rewritten into another subject", async () => {
	const decision = await evaluatePolicy("u1", () => "allow");

	expect(Reflect.set(decision, "subject", "admin")).toBe(false);

	const result = issueSession(decision);
	expect(result.ok && result.value.subject).toBe("u1");
});

test("an asynchronous policy is awaited", async () => {
	const allowed = await evaluatePolicy("u1", async () => "allow");
	const denied = await evaluatePolicy("u1", async () => "deny");
	const rejected = await evaluatePolicy("u1", async () => {
		throw new Error("boom");
	});

	expect(issueSession(allowed).ok).toBe(true);
	expect(issueSession(denied).ok).toBe(false);
	expect(issueSession(rejected).ok).toBe(false);
});

test("a session id is a 256-bit secret, different every time", async () => {
	const first = issueSession(await evaluatePolicy("u1", () => "allow"));
	const second = issueSession(await evaluatePolicy("u1", () => "allow"));

	expect(first.ok && first.value.id).toMatch(/^[0-9a-f]{64}$/);
	expect(first.ok && second.ok && first.value.id !== second.value.id).toBe(
		true,
	);
});
