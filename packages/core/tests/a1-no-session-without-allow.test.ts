import { evaluatePolicy, issueSession } from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

test("allow from evaluatePolicy yields a session", () => {
	const result = issueSession(evaluatePolicy("u1", () => "allow"));
	expect(result.ok && result.value.subject).toBe("u1");
});

test("any policy output other than exact 'allow' yields no session", () => {
	fastCheck.assert(
		fastCheck.property(fastCheck.anything(), (verdict) => {
			fastCheck.pre(verdict !== "allow");
			expect(issueSession(evaluatePolicy("u1", () => verdict)).ok).toBe(false);
		}),
	);
});

test("a throwing policy yields no session", () => {
	const decision = evaluatePolicy("u1", () => {
		throw new Error("boom");
	});
	expect(issueSession(decision).ok).toBe(false);
});

test("forged decisions yield no session", () => {
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

test("an issued allow decision cannot be rewritten into another subject", () => {
	const decision = evaluatePolicy("u1", () => "allow");

	expect(() => {
		(decision as { subject: string }).subject = "admin";
	}).toThrow(TypeError);

	const result = issueSession(decision);
	expect(result.ok && result.value.subject).toBe("u1");
});
