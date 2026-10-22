import {
	checkOrigin,
	clearCookie,
	clientAddress,
	readBearerToken,
	readCookie,
	serializeCookie,
} from "@vow-auth/http";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

const session = {
	name: "__Host-vow-session",
	sameSite: "lax",
	secure: true,
	maxAgeSeconds: 3_600,
} as const;

const withHeaders = (headers: Record<string, string>, method = "POST") =>
	new Request("https://app.example.com/x", { method, headers });

test("a cookie is HttpOnly, Secure, host-only, with an explicit SameSite and an end", () => {
	expect(serializeCookie(session, "abc.DEF_123-xyz")).toBe(
		"__Host-vow-session=abc.DEF_123-xyz; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax",
	);
	expect(serializeCookie({ ...session, sameSite: "strict" }, "v")).toContain(
		"SameSite=Strict",
	);
	expect(serializeCookie(session, "v")).not.toContain("Domain");
});

test("forgetting a cookie carries the attributes it was set with", () => {
	expect(clearCookie(session)).toBe(
		"__Host-vow-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
	);
});

test("a value or a name that a header cannot carry is refused, not escaped", () => {
	for (const value of [
		"a;b",
		"a b",
		"a,b",
		'a"b',
		"a\\b",
		"a\nb",
		"a\r\nSet-Cookie: x=y",
		"é",
	]) {
		expect(() => serializeCookie(session, value), value).toThrow(RangeError);
	}

	for (const name of ["", "a b", "a;b", "a=b", "é"]) {
		expect(() => serializeCookie({ ...session, name }, "v"), name).toThrow(
			RangeError,
		);
	}

	expect(() =>
		serializeCookie({ ...session, name: "__Host-x", secure: false }, "v"),
	).toThrow(RangeError);
	expect(
		serializeCookie({ ...session, name: "vow-session", secure: false }, "v"),
	).not.toContain("Secure");
});

test("no value of the safe alphabet can break out of its header", () => {
	fastCheck.assert(
		fastCheck.property(
			fastCheck.stringMatching(/^[A-Za-z0-9._~+/=-]{1,200}$/),
			(value) => {
				const header = serializeCookie(session, value);

				expect(header.split(";")).toHaveLength(6);
				expect(header).not.toMatch(/[\r\n]/);
			},
		),
		{ numRuns: 300 },
	);
});

test("a cookie is read by name, once; a name that appears twice reads as absent", () => {
	const read = (cookie: string) =>
		readCookie(withHeaders({ cookie }), "__Host-vow-session");

	expect(read("__Host-vow-session=abc")).toBe("abc");
	expect(read("a=1; __Host-vow-session=abc; b=2")).toBe("abc");
	expect(read("x__Host-vow-session=abc")).toBeUndefined();
	expect(read("__Host-vow-session=")).toBeUndefined();
	expect(
		read("__Host-vow-session=abc; __Host-vow-session=evil"),
	).toBeUndefined();
	expect(read("")).toBeUndefined();
	expect(readCookie(withHeaders({}), "__Host-vow-session")).toBeUndefined();
});

const allowed = new Set([
	"https://app.example.com",
	"https://admin.example.com:8443",
]);
const verdictOf = (headers: Record<string, string>, method = "POST") =>
	checkOrigin(withHeaders(headers, method), allowed);

test("a request that changes something must come from a page of the application", () => {
	for (const headers of [
		{ origin: "https://app.example.com", "sec-fetch-site": "same-origin" },
		{ origin: "https://app.example.com" },
		{ origin: "https://admin.example.com:8443", "sec-fetch-site": "same-site" },
		{ referer: "https://app.example.com/page?x=1" },
		{ "sec-fetch-site": "same-origin" },
	]) {
		expect(verdictOf(headers).ok, JSON.stringify(headers)).toBe(true);
	}
});

test("every other way of arriving is refused, with the reason", () => {
	const refused: readonly [Record<string, string>, string][] = [
		[
			{ origin: "https://app.example.com", "sec-fetch-site": "cross-site" },
			"cross-site",
		],
		[
			{ origin: "https://app.example.com", "sec-fetch-site": "none" },
			"not-a-navigation",
		],
		[{ origin: "null" }, "null-origin"],
		[{ origin: "https://evil.com" }, "unknown-origin"],
		[{ origin: "https://app.example.com.evil.com" }, "unknown-origin"],
		[
			{ origin: "https://evil.com", referer: "https://app.example.com/" },
			"unknown-origin",
		],
		[{ origin: "http://app.example.com" }, "unknown-origin"],
		[{ origin: "https://app.example.com:444" }, "unknown-origin"],
		[{ origin: "https://admin.example.com" }, "unknown-origin"],
		[{ origin: "app.example.com" }, "no-origin"],
		[
			{ referer: "https://evil.com/https://app.example.com/" },
			"unknown-origin",
		],
		[{}, "no-origin"],
		[{ "sec-fetch-site": "same-site" }, "no-origin"],
	];

	for (const [headers, reason] of refused) {
		expect(verdictOf(headers), JSON.stringify(headers)).toEqual({
			ok: false,
			reason,
		});
	}
});

test("a request that cannot change anything is not checked", () => {
	for (const method of ["GET", "HEAD", "OPTIONS"]) {
		expect(verdictOf({ "sec-fetch-site": "cross-site" }, method).ok).toBe(true);
	}
});

test("only an origin that is on the list exactly is accepted, whatever else is sent", () => {
	fastCheck.assert(
		fastCheck.property(fastCheck.string(), (origin) => {
			fastCheck.pre(!allowed.has(origin));

			expect(verdictOf({ origin }).ok).toBe(false);
		}),
		{ numRuns: 500 },
	);
});

test("the token is the one thing after the scheme of one header", () => {
	const token = (authorization: string | undefined) =>
		readBearerToken(
			withHeaders(authorization === undefined ? {} : { authorization }),
		);

	expect(token("Bearer abc.DEF-1_2~3+4/5==")).toBe("abc.DEF-1_2~3+4/5==");
	expect(token("bearer abc")).toBe("abc");
	expect(token("BEARER abc")).toBe("abc");

	for (const bad of [
		undefined,
		"",
		"Bearer",
		"Bearer ",
		"Bearer abc def",
		"Bearer abc, Bearer def",
		"Basic abc",
		"Token abc",
		"Bearer  abc",
		"Bearer abc;x",
		"Bearer a\tb",
	]) {
		expect(token(bad), String(bad)).toBeUndefined();
	}
});

test("a token in the query is never read", () => {
	expect(
		readBearerToken(
			new Request("https://app.example.com/session?access_token=abc"),
		),
	).toBeUndefined();
});

test("the address of the client is read from the one header that is named, and an IPv6 address is cut to its /64", () => {
	const address = (value: string | undefined, header = "cf-connecting-ip") =>
		clientAddress(withHeaders(value === undefined ? {} : { [header]: value }), {
			header: "cf-connecting-ip",
		});

	expect(address("203.0.113.7")).toBe("203.0.113.7");
	expect(address(" 203.0.113.7 ")).toBe("203.0.113.7");
	expect(address("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
	expect(address("2001:db8:1:2::1")).toBe("2001:db8:1:2::/64");
	expect(address("2001:0DB8:0001:0002:ffff:ffff:ffff:ffff")).toBe(
		"2001:db8:1:2::/64",
	);
	expect(address("2001:db8::1")).toBe("2001:db8:0:0::/64");
	expect(address("::1")).toBe("0:0:0:0::/64");
	expect(address("203.0.113.7", "x-forwarded-for")).toBeUndefined();

	for (const bad of [
		undefined,
		"",
		"203.0.113.7, 198.51.100.1",
		"not an address",
		"1.2.3",
		"1.2.3.4.5",
		"2001:db8::1::2",
		"2001:db8:1:2:3:4:5:6:7",
		"gggg::1",
		"a".repeat(65),
	]) {
		expect(address(bad), String(bad)).toBeUndefined();
	}
});

test("two addresses of one /64 are one client", () => {
	fastCheck.assert(
		fastCheck.property(
			fastCheck.array(fastCheck.integer({ min: 0, max: 0xffff }), {
				minLength: 8,
				maxLength: 8,
			}),
			fastCheck.array(fastCheck.integer({ min: 0, max: 0xffff }), {
				minLength: 4,
				maxLength: 4,
			}),
			(groups, otherTail) => {
				const text = (parts: readonly number[]) =>
					parts.map((part) => part.toString(16)).join(":");
				const first = clientAddress(
					withHeaders({ "cf-connecting-ip": text(groups) }),
					{ header: "cf-connecting-ip" },
				);
				const second = clientAddress(
					withHeaders({
						"cf-connecting-ip": text([...groups.slice(0, 4), ...otherTail]),
					}),
					{ header: "cf-connecting-ip" },
				);

				expect(first).toBeDefined();
				expect(first).toBe(second);
			},
		),
		{ numRuns: 300 },
	);
});
