import { defineDuration } from "@vow-auth/core";
import { createSealer, type SecretVersion } from "@vow-auth/core/internal";
import { durationOf } from "@vow-auth/test-support";
import fastCheck from "fast-check";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(1_000);
});

afterEach(() => {
	vi.useRealTimers();
});

const firstSecret: SecretVersion = {
	version: 1,
	value: "first-secret-0123456789abcdefghijklmnop",
};
const secondSecret: SecretVersion = {
	version: 2,
	value: "second-secret-0123456789abcdefghijklmno",
};

const sealOAuthState = (secrets: readonly SecretVersion[]) => {
	return createSealer({ secrets }).seal({
		purpose: "oauth-state",
		payload: { codeVerifier: "verifier" },
		timeToLive: durationOf(600_000),
	});
};

test("a sealed value unseals to its payload for its purpose only", async () => {
	const sealer = createSealer({ secrets: [firstSecret] });
	const sealed = await sealOAuthState([firstSecret]);

	const right = await sealer.unseal(sealed, "oauth-state");
	const wrong = await sealer.unseal(sealed, "email-link");

	expect(right.ok && right.value).toEqual({ codeVerifier: "verifier" });
	expect(wrong).toEqual({ ok: false, error: "invalid-seal" });
});

test("a sealed value is not one-time and unseals until it expires", async () => {
	const sealer = createSealer({ secrets: [firstSecret] });
	const sealed = await sealOAuthState([firstSecret]);

	vi.advanceTimersByTime(599_999);
	expect((await sealer.unseal(sealed, "oauth-state")).ok).toBe(true);
	expect((await sealer.unseal(sealed, "oauth-state")).ok).toBe(true);

	vi.advanceTimersByTime(1);
	expect((await sealer.unseal(sealed, "oauth-state")).ok).toBe(false);
});

test("any changed character makes a sealed value invalid", async () => {
	const sealer = createSealer({ secrets: [firstSecret] });
	const sealed = await sealOAuthState([firstSecret]);
	const alphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";

	await fastCheck.assert(
		fastCheck.asyncProperty(
			fastCheck.integer({ min: 0, max: sealed.length - 1 }),
			fastCheck.constantFrom(...alphabet),
			async (position, replacement) => {
				fastCheck.pre(sealed[position] !== replacement);
				const tampered =
					sealed.slice(0, position) + replacement + sealed.slice(position + 1);

				expect((await sealer.unseal(tampered, "oauth-state")).ok).toBe(false);
			},
		),
	);
});

test("arbitrary strings never unseal and never throw", async () => {
	const sealer = createSealer({ secrets: [firstSecret] });

	await fastCheck.assert(
		fastCheck.asyncProperty(fastCheck.string(), async (guess) => {
			expect(await sealer.unseal(guess, "oauth-state")).toEqual({
				ok: false,
				error: "invalid-seal",
			});
		}),
	);
});

test("a rotation keeps old values valid until the old secret is removed", async () => {
	const sealedBefore = await sealOAuthState([firstSecret]);
	const rotated = createSealer({ secrets: [secondSecret, firstSecret] });
	const sealedAfter = await sealOAuthState([secondSecret, firstSecret]);
	const retired = createSealer({ secrets: [secondSecret] });

	expect(sealedAfter.startsWith("2.")).toBe(true);
	expect((await rotated.unseal(sealedBefore, "oauth-state")).ok).toBe(true);
	expect((await retired.unseal(sealedBefore, "oauth-state")).ok).toBe(false);
	expect((await retired.unseal(sealedAfter, "oauth-state")).ok).toBe(true);
});

test("a value sealed with another secret of the same version is rejected", async () => {
	const sealed = await sealOAuthState([firstSecret]);
	const impostor = createSealer({
		secrets: [{ version: 1, value: secondSecret.value }],
	});

	expect((await impostor.unseal(sealed, "oauth-state")).ok).toBe(false);
});

test("sealing the same input twice gives different values", async () => {
	const first = await sealOAuthState([firstSecret]);
	const second = await sealOAuthState([firstSecret]);

	expect(first).not.toBe(second);
});

test("weak or inconsistent secrets are a configuration error", () => {
	for (const secrets of [
		[],
		[{ version: 1, value: "too-short" }],
		[firstSecret, { version: 1, value: secondSecret.value }],
		[{ version: -1, value: firstSecret.value }],
		[{ version: 1.5, value: firstSecret.value }],
	]) {
		expect(() => createSealer({ secrets })).toThrow(RangeError);
	}
});

test("A26: a lifetime the core cannot use is refused where it is defined, and a look-alike is refused where it is used", async () => {
	const sealer = createSealer({ secrets: [firstSecret] });

	for (const milliseconds of [Number.NaN, 0, -1, Infinity, -Infinity]) {
		expect(defineDuration(milliseconds)).toEqual({
			ok: false,
			error: "invalid-request",
		});
	}

	await expect(
		sealer.seal({
			purpose: "oauth-state",
			// @ts-expect-error a look-alike that did not come from defineDuration
			timeToLive: { milliseconds: 1_000 },
		}),
	).rejects.toThrow(TypeError);
});

test("a malformed value or an unknown version never reaches the cryptography", async () => {
	const sealer = createSealer({ secrets: [firstSecret] });
	const deriveKey = vi.spyOn(crypto.subtle, "deriveKey");

	try {
		await sealer.unseal("1.not base64", "oauth-state");
		await sealer.unseal("7.AAAA", "oauth-state");

		expect(deriveKey).not.toHaveBeenCalled();
	} finally {
		deriveKey.mockRestore();
	}
});
