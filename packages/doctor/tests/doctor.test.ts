import { fileURLToPath } from "node:url";
import { EXIT_CODES, formatReport, main, runDoctor } from "@vow-auth/doctor";
import { expect, test } from "vitest";
import {
	forgetfulTokenStore,
	goodOptions,
	goodTarget,
	nonAtomicTokenStore,
	passthroughFactor,
	splitBrainIdentityStore,
	strictFactor,
	stuckEpochStore,
	tenantBlindIdentityStore,
	unlimitedMeterStore,
} from "./support.js";

const idsOf = async (target: Parameters<typeof runDoctor>[0]) => {
	const report = await runDoctor(target);

	return report.findings.map((finding) => finding.id);
};

test("A16: a sound configuration passes every check and finds nothing", async () => {
	const report = await runDoctor(goodTarget());

	expect(report.findings).toEqual([]);
	expect(report.suppressed).toEqual([]);
	expect(report.passed).toHaveLength(7);
});

test("A16: a token store whose take is not atomic is found, with the steps to use it", async () => {
	const report = await runDoctor({
		options: { ...goodOptions(), tokenStore: nonAtomicTokenStore() },
	});
	const [finding] = report.findings;

	expect(report.findings.map((item) => item.id)).toEqual([
		"token-store-not-atomic",
	]);
	expect(finding?.level).toBe("error");
	expect(finding?.scenario).toHaveLength(3);
	expect(finding?.scenario.join(" ")).toContain("one-time");
	expect(finding?.fix).toContain("atomic");
});

test("A16: a token store that loses records is found", async () => {
	expect(
		await idsOf({
			options: { ...goodOptions(), tokenStore: forgetfulTokenStore() },
		}),
	).toEqual(["token-store-loses-records"]);
});

test("A16: an epoch store whose stamp does not rise is found", async () => {
	expect(
		await idsOf({ options: { ...goodOptions(), epochs: stuckEpochStore() } }),
	).toEqual(["epoch-store-stamp-not-rising"]);
});

test("A16: a meter store that does not hold its limit is found", async () => {
	expect(
		await idsOf({
			options: { ...goodOptions(), meterStore: unlimitedMeterStore() },
		}),
	).toEqual(["meter-store-over-allows"]);
});

test("A16: an identity store that is not first-wins is found", async () => {
	expect(
		await idsOf({
			options: { ...goodOptions(), identities: splitBrainIdentityStore() },
		}),
	).toContain("identity-store-not-first-wins");
});

test("A16: an identity store that crosses tenants is found", async () => {
	expect(
		await idsOf({
			options: { ...goodOptions(), identities: tenantBlindIdentityStore() },
		}),
	).toEqual(["identity-store-crosses-tenants"]);
});

test("A16: a factor that proves claims from a response that proves nothing is found", async () => {
	const report = await runDoctor({
		options: goodOptions(),
		factors: [strictFactor, passthroughFactor],
	});

	expect(report.findings.map((finding) => finding.id)).toEqual([
		"factor-accepts-empty-evidence",
	]);
	expect(report.findings[0]?.title).toContain("passthrough");
});

test("A16: guessable secrets are found, and random ones are not", async () => {
	for (const value of [
		"a".repeat(40),
		"abcabcabcabcabcabcabcabcabcabcabcabcabc",
		"0123456789012345678901234567890123456789",
		"my-changeme-0123456789-Zq8xLw4Rt7Yp",
		"Password-Password-Password-Password-1",
		"aabbaabbaabbaabbaabbaabbaabbaabbaabbaabb",
	]) {
		expect(
			await idsOf({
				options: { ...goodOptions(), secrets: [{ version: 1, value }] },
			}),
			value,
		).toEqual(["secrets-low-entropy"]);
	}

	for (let attempt = 0; attempt < 200; attempt += 1) {
		expect(await idsOf(goodTarget())).toEqual([]);
	}
});

test("A16: options the core refuses are reported, not thrown", async () => {
	const report = await runDoctor({
		options: { ...goodOptions(), secrets: [] },
	});

	expect(report.findings.map((finding) => finding.id)).toContain(
		"config-refused",
	);
});

test("A16: a store that cannot be probed counts as failed", async () => {
	const report = await runDoctor({
		options: {
			...goodOptions(),
			tokenStore: {
				put: async () => {
					throw new Error("connection refused");
				},
				take: async () => undefined,
			},
		},
	});

	expect(report.findings).toHaveLength(1);
	expect(report.findings[0]).toMatchObject({
		id: "token-store-not-atomic",
		level: "error",
	});
	expect(report.findings[0]?.scenario.join(" ")).toContain(
		"connection refused",
	);
});

test("a suppressed finding leaves the verdict and stays in the report", async () => {
	const report = await runDoctor({
		options: { ...goodOptions(), tokenStore: nonAtomicTokenStore() },
		suppress: ["token-store-not-atomic"],
	});

	expect(report.findings).toEqual([]);
	expect(report.suppressed.map((finding) => finding.id)).toEqual([
		"token-store-not-atomic",
	]);
	expect(formatReport(report)).toContain("SKIP  token-store-not-atomic");
});

test("the report names the problem, the steps and the fix", async () => {
	const text = formatReport(
		await runDoctor({
			options: { ...goodOptions(), tokenStore: nonAtomicTokenStore() },
		}),
	);

	expect(text).toContain("ERROR token-store-not-atomic");
	expect(text).toContain("How it is exploited:");
	expect(text).toContain("1. ");
	expect(text).toContain("Fix: ");
	expect(text).toContain('suppress: ["token-store-not-atomic"]');
	expect(text).toContain("1 errors, 0 warnings");
});

const fixture = (name: string): string =>
	fileURLToPath(new URL(`./fixtures/${name}.ts`, import.meta.url));

test("A16: the command exits 0 on a sound configuration", async () => {
	const lines: string[] = [];

	expect(await main([fixture("good")], (line) => lines.push(line))).toBe(
		EXIT_CODES.clean,
	);
	expect(lines.join("\n")).toContain("0 errors");
});

test("A16: the command exits 1 on a broken configuration and prints the scenario", async () => {
	const lines: string[] = [];

	expect(await main([fixture("broken")], (line) => lines.push(line))).toBe(
		EXIT_CODES.findings,
	);
	expect(lines.join("\n")).toContain("How it is exploited:");
});

test("the command exits 2 when it cannot run", async () => {
	for (const argv of [[], [fixture("missing")], [fixture("wrong-shape")]]) {
		const lines: string[] = [];

		expect(await main(argv, (line) => lines.push(line))).toBe(
			EXIT_CODES.notRun,
		);
		expect(lines.length).toBeGreaterThan(0);
	}
});
