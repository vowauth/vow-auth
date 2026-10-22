import {
	createOutboundGuard,
	createRedirectPolicy,
	isPublicAddress,
} from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test, vi } from "vitest";

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

test("A15: addresses that are not public are recognized, in every spelling", () => {
	const blocked = [
		"0.0.0.0",
		"10.1.2.3",
		"100.64.0.1",
		"100.127.255.255",
		"127.0.0.1",
		"127.255.255.254",
		"169.254.169.254",
		"172.16.0.1",
		"172.31.255.255",
		"192.0.0.1",
		"192.0.2.1",
		"192.168.1.1",
		"198.18.0.1",
		"198.19.255.255",
		"198.51.100.1",
		"203.0.113.9",
		"224.0.0.1",
		"239.255.255.255",
		"240.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"[::1]",
		"fe80::1",
		"fc00::1",
		"fd12:3456::1",
		"fec0::1",
		"ff02::1",
		"::ffff:127.0.0.1",
		"::ffff:7f00:1",
		"::ffff:10.0.0.1",
		"::ffff:169.254.169.254",
		"64:ff9b::7f00:1",
		"64:ff9b::10.0.0.1",
		"2002:7f00:1::",
		"2002:a9fe:a9fe::1",
		"2001:db8::1",
		"2001::1",
		"3fff::1",
		"100::1",
		"0:0:0:0:0:0:0:1",
		"1.2.3",
		"1.2.3.4.5",
		"0x7f.0.0.1",
		"2130706433",
		"0177.0.0.1",
		"127.1",
		"256.1.1.1",
		"1.2.3.04",
		"example.com",
		"",
		"::g",
		"1::2::3",
		"12345::1",
	];

	for (const address of blocked) {
		expect(isPublicAddress(address), address).toBe(false);
	}
});

test("A15: public addresses are recognized", () => {
	for (const address of [
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"172.15.255.255",
		"172.32.0.1",
		"100.63.255.255",
		"100.128.0.1",
		"192.0.3.1",
		"198.17.255.255",
		"198.20.0.1",
		"2606:4700:4700::1111",
		"2a00:1450:4001::200e",
		"[2606:4700:4700::1111]",
		"::ffff:8.8.8.8",
		"64:ff9b::808:808",
		"2002:808:808::1",
	]) {
		expect(isPublicAddress(address), address).toBe(true);
	}
});

test("A15: no address the URL parser reads as private passes, whatever its spelling", () => {
	fastCheck.assert(
		fastCheck.property(
			fastCheck.constantFrom(
				"127.0.0.1",
				"10.0.0.1",
				"169.254.169.254",
				"192.168.0.1",
			),
			fastCheck.constantFrom(
				(address: string) => address,
				(address: string) =>
					`0x${address
						.split(".")
						.map((part) => Number(part).toString(16).padStart(2, "0"))
						.join("")}`,
				(address: string) =>
					address
						.split(".")
						.map((part) => `0${Number(part).toString(8)}`)
						.join("."),
				(address: string) =>
					String(
						address
							.split(".")
							.reduce((sum, part) => sum * 256 + Number(part), 0),
					),
				(address: string) => `::ffff:${address}`,
				(address: string) => `64:ff9b::${address}`,
			),
			(address, spell) => {
				const spelled = spell(address);
				const host = spelled.includes(":") ? `[${spelled}]` : spelled;
				const normalized = URL.canParse(`https://${host}/`)
					? new URL(`https://${host}/`).hostname
					: spelled;

				expect(isPublicAddress(normalized), `${spelled} -> ${normalized}`).toBe(
					false,
				);
				expect(isPublicAddress(spelled), spelled).toBe(false);
			},
		),
		{ numRuns: 200 },
	);
});

const guardWith = (
	options: Partial<Parameters<typeof createOutboundGuard>[0]> = {},
) => {
	const send = vi.fn(async () => new Response("ok"));

	return {
		send,
		guard: createOutboundGuard({
			allowedHosts: ["hooks.example.com", "api.partner.io"],
			fetch: send,
			...options,
		}),
	};
};

test("A15: a call goes only to https, default port, no credentials, a host of the list", async () => {
	const { guard, send } = guardWith();

	expect((await guard.fetch("https://hooks.example.com/in")).ok).toBe(true);
	expect((await guard.fetch("https://api.partner.io/x?y=1")).ok).toBe(true);
	expect(send).toHaveBeenCalledTimes(2);

	for (const target of [
		"http://hooks.example.com/",
		"https://hooks.example.com:8443/",
		"https://hooks.example.com:443@evil.com/",
		"https://user:pass@hooks.example.com/",
		"https://evil.com/",
		"https://hooks.example.com.evil.com/",
		"https://sub.hooks.example.com/",
		"https://127.0.0.1/",
		"https://[::1]/",
		"https://169.254.169.254/latest/meta-data/",
		"https://0x7f000001/",
		"https://2130706433/",
		"https://localhost/",
		"ftp://hooks.example.com/",
		"file:///etc/passwd",
		"gopher://hooks.example.com/",
		"not a url",
		"",
		42,
		undefined,
	]) {
		expect(await guard.fetch(target), String(target)).toEqual({
			ok: false,
			error: "forbidden",
		});
	}

	expect(send).toHaveBeenCalledTimes(2);
});

test("A15: the guard forbids redirects and caching on the call it makes", async () => {
	const { guard, send } = guardWith();

	await guard.fetch("https://hooks.example.com/in", {
		method: "POST",
		body: "x",
	});

	const [, init] = send.mock.calls[0] as unknown as [URL, RequestInit];

	expect(init).toMatchObject({
		method: "POST",
		redirect: "error",
		cache: "no-store",
	});
});

test("A15: a redirect that the server answers is not followed, and a failed call is unavailable", async () => {
	const { guard } = guardWith({
		fetch: async () => {
			throw new TypeError("redirect mode is set to error");
		},
	});

	expect(await guard.fetch("https://hooks.example.com/in")).toEqual({
		ok: false,
		error: "unavailable",
	});
});

test("A15: with names resolved, one private address among the answers refuses the call", async () => {
	const answers: Record<string, string[]> = {
		"hooks.example.com": ["93.184.216.34", "2606:4700:4700::1111"],
		"api.partner.io": ["93.184.216.34", "10.0.0.5"],
	};
	const { guard, send } = guardWith({
		resolveAddresses: async (host) => answers[host] ?? [],
	});

	expect((await guard.fetch("https://hooks.example.com/")).ok).toBe(true);
	expect(await guard.fetch("https://api.partner.io/")).toEqual({
		ok: false,
		error: "forbidden",
	});
	expect(send).toHaveBeenCalledTimes(1);
});

test("A15: a resolver that finds nothing or fails refuses the call", async () => {
	for (const resolveAddresses of [
		async () => [],
		async () => {
			throw new Error("SERVFAIL");
		},
	]) {
		const { guard, send } = guardWith({ resolveAddresses });

		expect(await guard.check("https://hooks.example.com/")).toEqual({
			ok: false,
			error: "forbidden",
		});
		expect(send).not.toHaveBeenCalled();
	}
});

test("a list of hosts must be canonical names, not addresses, ports or patterns", () => {
	for (const entry of [
		"Hooks.Example.com",
		"*.example.com",
		"hooks.example.com:443",
		"https://hooks.example.com",
		"hooks.example.com/path",
		"127.0.0.1",
		"[::1]",
		"",
	]) {
		expect(() => createOutboundGuard({ allowedHosts: [entry] }), entry).toThrow(
			RangeError,
		);
	}
});
