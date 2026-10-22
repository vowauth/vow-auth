import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

const readJson = (name: string): Record<string, unknown> => {
	const parsed: unknown = JSON.parse(
		readFileSync(new URL(`../${name}`, import.meta.url), "utf8"),
	);

	if (typeof parsed !== "object" || parsed === null) {
		throw new Error(`${name} must hold an object`);
	}

	return Object.fromEntries(Object.entries(parsed));
};

test("A14: the published package has one entry, and the building blocks are not built into it", () => {
	const manifest = readJson("package.json");
	const compiler = readJson("tsconfig.json");
	const exported = manifest.exports;

	expect(typeof exported === "object" && exported !== null).toBe(true);
	expect(Object.keys(exported ?? {})).toEqual(["."]);
	expect(JSON.stringify(manifest)).not.toContain("internal");
	expect(compiler.exclude).toContain("src/internal.ts");
});
