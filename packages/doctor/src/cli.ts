import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { DoctorTarget } from "./finding.js";
import { formatReport } from "./format-report.js";
import { runDoctor } from "./run-doctor.js";

/** Exit codes of the command. */
export const EXIT_CODES = {
	clean: 0,
	findings: 1,
	notRun: 2,
} as const;

const USAGE =
	"usage: vow-auth-doctor <module>\nThe module's default export is { options, factors?, suppress? }, or a function that returns it.";

const isTarget = (value: unknown): value is DoctorTarget => {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "options") === "object" &&
		Reflect.get(value, "options") !== null
	);
};

const load = async (path: string): Promise<DoctorTarget> => {
	const loaded: unknown = await import(pathToFileURL(resolve(path)).href);
	const exported =
		typeof loaded === "object" && loaded !== null
			? Reflect.get(loaded, "default")
			: undefined;
	const target: unknown =
		typeof exported === "function" ? await exported() : exported;

	if (!isTarget(target)) {
		throw new TypeError(
			"the default export must be { options, factors?, suppress? }",
		);
	}

	return target;
};

/**
 * Runs the command: loads the module, runs the doctor and prints the report.
 * It returns the exit code instead of exiting, so it can be tested.
 */
export async function main(
	argv: readonly string[],
	print: (text: string) => void,
): Promise<number> {
	const [path] = argv;

	if (path === undefined) {
		print(USAGE);

		return EXIT_CODES.notRun;
	}

	try {
		const report = await runDoctor(await load(path));

		print(formatReport(report));

		return report.findings.some((finding) => finding.level === "error")
			? EXIT_CODES.findings
			: EXIT_CODES.clean;
	} catch (error) {
		print(
			`vow-auth doctor could not run: ${error instanceof Error ? error.message : String(error)}`,
		);

		return EXIT_CODES.notRun;
	}
}
