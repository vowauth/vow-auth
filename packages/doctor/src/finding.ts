import type { AuthOptions, Factor } from "@vow-auth/core";

/** How serious a finding is. An error makes the doctor exit with a failure. */
export type FindingLevel = "error" | "warning";

/** A problem the doctor found, with the shortest way to exploit it. */
export type Finding = {
	/** Also the key that suppresses the finding. */
	readonly id: string;
	readonly level: FindingLevel;
	readonly title: string;
	/** The shortest steps by which an attacker uses the problem. */
	readonly scenario: readonly string[];
	readonly fix: string;
};

/** What the doctor examines: the options given to `createAuth` and the factors in use. */
export type DoctorTarget = {
	readonly options: AuthOptions;
	readonly factors?: readonly Factor[];
	/** Ids of findings to leave out of the verdict, each a decision someone made. */
	readonly suppress?: readonly string[];
};

/** One group of probes. It returns what it found; nothing found means it passed. */
export type Check = {
	readonly id: string;
	readonly title: string;
	run(target: DoctorTarget): Promise<readonly Finding[]>;
};

/** The outcome of a run. */
export type DoctorReport = {
	readonly findings: readonly Finding[];
	readonly suppressed: readonly Finding[];
	/** Titles of the checks that found nothing. */
	readonly passed: readonly string[];
};
