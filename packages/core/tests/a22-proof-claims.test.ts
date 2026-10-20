import {
	type Factor,
	fail,
	type Result,
	succeed,
	verifyProof,
} from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

const factorReturning = (outcome: () => Result<unknown>): Factor => ({
	id: "test-factor",
	strength: "possession",
	verify: async () => outcome(),
});

const validClaims = {
	provider: "email",
	externalId: "a@example.com",
	email: "a@example.com",
	emailVerified: true,
};

test("a proof carries the factor identity and validated claims", async () => {
	const result = await verifyProof(
		factorReturning(() => succeed(validClaims)),
		undefined,
		{ now: () => 42 },
	);

	expect(result.ok && result.value).toEqual({
		factor: "test-factor",
		strength: "possession",
		verifiedAtMilliseconds: 42,
		claims: validClaims,
	});
});

test("a proof is frozen", async () => {
	const result = await verifyProof(
		factorReturning(() => succeed(validClaims)),
		undefined,
	);

	expect(result.ok && Object.isFrozen(result.value)).toBe(true);
	expect(result.ok && Object.isFrozen(result.value.claims)).toBe(true);
});

test("a rejected, throwing or rejecting factor yields the same error", async () => {
	const rejected = await verifyProof(
		factorReturning(() => fail("bad-code")),
		undefined,
	);
	const throwing = await verifyProof(
		factorReturning(() => {
			throw new Error("boom");
		}),
		undefined,
	);
	const rejecting = await verifyProof(
		{
			id: "f",
			strength: "possession",
			verify: () => Promise.reject(new Error("boom")),
		},
		undefined,
	);

	for (const result of [rejected, throwing, rejecting]) {
		expect(!result.ok && result.error).toBe("invalid-proof");
	}
});

test("claims with prototype keys are refused", async () => {
	for (const key of ["__proto__", "constructor", "prototype"]) {
		const claims = JSON.parse(
			`{"provider":"p","externalId":"e","emailVerified":false,"${key}":{"emailVerified":true}}`,
		);
		const result = await verifyProof(
			factorReturning(() => succeed(claims)),
			undefined,
		);

		expect(result.ok, key).toBe(false);
	}
});

test("claims with unknown keys are refused", async () => {
	const result = await verifyProof(
		factorReturning(() => succeed({ ...validClaims, role: "admin" })),
		undefined,
	);

	expect(result.ok).toBe(false);
});

test("malformed claims are refused", async () => {
	for (const claims of [
		null,
		[],
		"claims",
		{},
		{ ...validClaims, provider: "" },
		{ ...validClaims, externalId: 1 },
		{ ...validClaims, emailVerified: "true" },
		{ ...validClaims, emailVerified: 1 },
		{ provider: "p", externalId: "e", emailVerified: true },
		{ ...validClaims, email: "" },
	]) {
		const result = await verifyProof(
			factorReturning(() => succeed(claims)),
			undefined,
		);

		expect(result.ok, JSON.stringify(claims)).toBe(false);
	}
});

test("arbitrary claim values never produce a verified email without an email", async () => {
	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.anything(), async (claims) => {
			const result = await verifyProof(
				factorReturning(() => succeed(claims)),
				undefined,
			);

			if (result.ok) {
				expect(
					!result.value.claims.emailVerified ||
						result.value.claims.email !== undefined,
				).toBe(true);
			}
		}),
	);
});

test("inherited properties never supply claims", async () => {
	Object.defineProperty(Object.prototype, "emailVerified", {
		value: true,
		configurable: true,
	});

	try {
		const result = await verifyProof(
			factorReturning(() => succeed({ provider: "p", externalId: "e" })),
			undefined,
		);

		expect(result.ok).toBe(false);
	} finally {
		Reflect.deleteProperty(Object.prototype, "emailVerified");
	}
});

test("the claims are copied, so the factor cannot change a minted proof", async () => {
	const claims = {
		...validClaims,
		emailVerified: false,
		email: "a@example.com",
	};
	const result = await verifyProof(
		factorReturning(() => succeed(claims)),
		undefined,
	);

	claims.emailVerified = true;

	expect(result.ok && result.value.claims.emailVerified).toBe(false);
});
