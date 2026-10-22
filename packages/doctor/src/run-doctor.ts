import { configCheck } from "./checks/config-check.js";
import { epochStoreCheck } from "./checks/epoch-store-check.js";
import { factorsCheck } from "./checks/factors-check.js";
import { identityStoreCheck } from "./checks/identity-store-check.js";
import { meterStoreCheck } from "./checks/meter-store-check.js";
import { secretsCheck } from "./checks/secrets-check.js";
import { tokenStoreCheck } from "./checks/token-store-check.js";
import type { Check, DoctorReport, DoctorTarget, Finding } from "./finding.js";

const CHECKS: readonly Check[] = [
	configCheck,
	secretsCheck,
	tokenStoreCheck,
	epochStoreCheck,
	meterStoreCheck,
	identityStoreCheck,
	factorsCheck,
];

const couldNotRun = (check: Check, error: unknown): Finding => {
	const message = error instanceof Error ? error.message : String(error);

	return {
		id: check.id,
		level: "error",
		title: `${check.title}: the probe could not run`,
		scenario: [
			`The probe threw "${message}"; what it checks cannot be told, so it counts as failed.`,
		],
		fix: "Make the store reachable from where the doctor runs, then run it again.",
	};
};

/**
 * Runs the checks against a target and returns the findings. A probe that
 * throws is a finding too: a store that cannot be probed is not proven safe.
 * The probes write only keys that start with `vow-doctor-` and tenants made
 * up for the run, and delete the subjects they create; run them against a
 * test environment or a scratch namespace.
 */
export async function runDoctor(target: DoctorTarget): Promise<DoctorReport> {
	const suppress = new Set(target.suppress ?? []);
	const findings: Finding[] = [];
	const suppressed: Finding[] = [];
	const passed: string[] = [];

	for (const check of CHECKS) {
		let found: readonly Finding[];

		try {
			found = await check.run(target);
		} catch (error) {
			found = [couldNotRun(check, error)];
		}

		if (found.length === 0) {
			passed.push(check.title);
		}

		for (const finding of found) {
			(suppress.has(finding.id) ? suppressed : findings).push(finding);
		}
	}

	return { findings, suppressed, passed };
}
