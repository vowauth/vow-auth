import { createRedirectPolicy } from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

const redirect = createRedirectPolicy({
	allowedOrigins: [
		"https://app.example.com",
		"https://admin.example.com:8443",
		"http://localhost:3000",
	],
});

const refused = { ok: false, error: "invalid-request" };

test("A15: a redirect to an origin of the list, or to a path of this site, is accepted", () => {
	expect(redirect("/dashboard?tab=1#top")).toEqual({
		ok: true,
		value: "/dashboard?tab=1#top",
	});
	expect(redirect("https://app.example.com/after?x=1")).toEqual({
		ok: true,
		value: "https://app.example.com/after?x=1",
	});
	expect(redirect("https://admin.example.com:8443/")).toMatchObject({
		ok: true,
	});
	expect(redirect("http://localhost:3000/cb")).toMatchObject({ ok: true });
});

test("A15: every way to leave the list is refused", () => {
	const attacks = [
		"https://evil.example.com/",
		"https://app.example.com.evil.com/",
		"https://evil.com/https://app.example.com",
		"https://app.example.com@evil.com/",
		"https://user:pass@app.example.com/",
		"https://app.example.com:444/",
		"http://app.example.com/",
		"https://admin.example.com/",
		"http://localhost:3001/",
		"//evil.com",
		"//evil.com/path",
		"/\\evil.com",
		"\\\\evil.com",
		"https://app.example.com\\@evil.com",
		"/ /evil.com",
		"/\t/evil.com",
		"/\n/evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>1</script>",
		"file:///etc/passwd",
		"HTTPS://EVIL.COM",
		"evil.com",
		"",
		" https://app.example.com/",
		"https://app.example.com/ ",
		"https://app.example.com%2f@evil.com/",
		`/${"a".repeat(3_000)}`,
	];

	for (const attack of attacks) {
		expect(redirect(attack), JSON.stringify(attack)).toEqual(refused);
	}

	for (const notText of [undefined, null, 1, {}, [], ["/ok"]]) {
		expect(redirect(notText)).toEqual(refused);
	}
});

const INVISIBLE_OR_SPACE_CODE_POINTS = [
	0x7f, 0x85, 0xa0, 0x2003, 0x2028, 0x2029, 0x3000, 0x200b, 0x200d, 0x202e,
	0xfeff, 0xd800, 0xe000,
];

test("A15: a target with an invisible character or a space of any script is refused", () => {
	for (const codePoint of INVISIBLE_OR_SPACE_CODE_POINTS) {
		const character = String.fromCharCode(codePoint);

		for (const target of [
			`/${character}/evil.com`,
			`/path${character}`,
			`https://app.example.com/${character}`,
			`https://app.example.com${character}.evil.com/`,
		]) {
			expect(redirect(target), codePoint.toString(16)).toEqual(refused);
		}
	}
});

test("A15: whatever the policy accepts leads to a path of this site or an origin of the list", () => {
	const allowed = new Set([
		"https://app.example.com",
		"https://admin.example.com:8443",
		"http://localhost:3000",
	]);

	fastCheck.assert(
		fastCheck.property(
			fastCheck.oneof(
				fastCheck.string({ maxLength: 40 }),
				fastCheck
					.tuple(
						fastCheck.constantFrom(
							"https://app.example.com",
							"//",
							"/",
							"https://",
						),
						fastCheck.string({ maxLength: 20 }),
						fastCheck.constantFrom("@evil.com", "\\", "%2f", "/", "#", "?", ""),
						fastCheck.string({ maxLength: 20 }),
					)
					.map((parts) => parts.join("")),
			),
			(target) => {
				const result = redirect(target);

				if (!result.ok) {
					return;
				}

				if (result.value.startsWith("/")) {
					expect(result.value.startsWith("//")).toBe(false);

					const resolved = new URL(result.value, "https://app.example.com");

					expect(resolved.origin).toBe("https://app.example.com");
				} else {
					expect(allowed.has(new URL(result.value).origin)).toBe(true);
				}
			},
		),
		{ numRuns: 2_000 },
	);
});

test("a list of origins must be exact origins, and http only for loopback", () => {
	for (const entry of [
		"https://*.example.com",
		"https://app.example.com/path",
		"https://app.example.com/",
		"http://app.example.com",
		"app.example.com",
		"",
		"javascript:alert(1)",
	]) {
		expect(
			() => createRedirectPolicy({ allowedOrigins: [entry] }),
			entry,
		).toThrow(RangeError);
	}

	expect(createRedirectPolicy({ allowedOrigins: [] })("https://x.com")).toEqual(
		refused,
	);
});
