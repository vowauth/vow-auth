import fastCheck from "fast-check";
import { expect, test } from "vitest";
import { decodeBase32, encodeBase32 } from "../src/base32.js";
import { findStep, generateCode, stepOf } from "../src/otp.js";

const RFC_SECRET = new TextEncoder().encode("12345678901234567890");

test("RFC 6238 appendix B: the codes of the SHA-1 test vectors, cut to six digits", async () => {
	const vectors: readonly (readonly [number, string])[] = [
		[59, "287082"],
		[1_111_111_109, "081804"],
		[1_111_111_111, "050471"],
		[1_234_567_890, "005924"],
		[2_000_000_000, "279037"],
		[20_000_000_000, "353130"],
	];

	for (const [seconds, code] of vectors) {
		expect(
			await generateCode(RFC_SECRET, stepOf(seconds * 1_000)),
			String(seconds),
		).toBe(code);
	}
});

test("a time step is 30 seconds long and starts at the epoch", () => {
	expect(stepOf(0)).toBe(0);
	expect(stepOf(29_999)).toBe(0);
	expect(stepOf(30_000)).toBe(1);
});

test("the current code and one step either way are accepted, two steps are not", async () => {
	const now = 1_111_111_111_000;
	const step = stepOf(now);

	for (const offset of [-1, 0, 1]) {
		expect(
			await findStep(
				RFC_SECRET,
				await generateCode(RFC_SECRET, step + offset),
				now,
			),
			String(offset),
		).toBe(step + offset);
	}

	for (const offset of [-2, 2, 10]) {
		expect(
			await findStep(
				RFC_SECRET,
				await generateCode(RFC_SECRET, step + offset),
				now,
			),
			String(offset),
		).toBeUndefined();
	}
});

test("anything but six digits is refused before any code is computed", async () => {
	for (const code of [
		"",
		"12345",
		"1234567",
		"12345a",
		" 123456",
		"123456 ",
		"１２３４５６",
	]) {
		expect(await findStep(RFC_SECRET, code, 59_000), code).toBeUndefined();
	}
});

test("a code from another secret is not accepted", async () => {
	const other = new TextEncoder().encode("09876543210987654321");
	const now = 59_000;

	expect(
		await findStep(RFC_SECRET, await generateCode(other, stepOf(now)), now),
	).toBeUndefined();
});

test("RFC 4648 test vectors for base32 without padding", () => {
	const vectors: readonly (readonly [string, string])[] = [
		["", ""],
		["f", "MY"],
		["fo", "MZXQ"],
		["foo", "MZXW6"],
		["foob", "MZXW6YQ"],
		["fooba", "MZXW6YTB"],
		["foobar", "MZXW6YTBOI"],
	];

	for (const [plain, encoded] of vectors) {
		expect(encodeBase32(new TextEncoder().encode(plain))).toBe(encoded);
		expect(new TextDecoder().decode(decodeBase32(encoded))).toBe(plain);
	}
});

test("base32 reads back what it wrote, and refuses other characters", () => {
	fastCheck.assert(
		fastCheck.property(fastCheck.uint8Array({ maxLength: 64 }), (bytes) => {
			expect(decodeBase32(encodeBase32(bytes))).toEqual(bytes);
		}),
		{ numRuns: 200 },
	);

	for (const text of ["mzxw6", "MZXW6=", "MZXW 6", "MZXW1", "é"]) {
		expect(decodeBase32(text), text).toBeUndefined();
	}
});
