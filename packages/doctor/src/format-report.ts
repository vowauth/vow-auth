import type { DoctorReport, Finding } from "./finding.js";

const INDENT = "  ";

const formatFinding = (finding: Finding): string[] => {
	const label = finding.level === "error" ? "ERROR" : "WARN ";

	return [
		`${label} ${finding.id}`,
		`${INDENT}${finding.title}`,
		`${INDENT}How it is exploited:`,
		...finding.scenario.map(
			(step, index) => `${INDENT}${INDENT}${index + 1}. ${step}`,
		),
		`${INDENT}Fix: ${finding.fix}`,
		`${INDENT}Suppress with: suppress: ["${finding.id}"]`,
		"",
	];
};

/** Renders a report as the text the command prints. */
export function formatReport(report: DoctorReport): string {
	const errors = report.findings.filter((finding) => finding.level === "error");
	const warnings = report.findings.length - errors.length;

	return [
		"vow-auth doctor",
		"",
		...report.passed.map((title) => `PASS  ${title}`),
		...report.suppressed.map((finding) => `SKIP  ${finding.id} (suppressed)`),
		...(report.passed.length + report.suppressed.length > 0 ? [""] : []),
		...report.findings.flatMap(formatFinding),
		`${errors.length} errors, ${warnings} warnings, ${report.passed.length} passed, ${report.suppressed.length} suppressed`,
	].join("\n");
}
