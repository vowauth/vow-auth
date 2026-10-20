import { readFileSync } from "node:fs";
import { extname } from "node:path";
import ts from "typescript";

const path = process.argv[2] ?? "";
const source = readFileSync(0, "utf8");
const scriptKinds = {
	".ts": ts.ScriptKind.TS,
	".mts": ts.ScriptKind.TS,
	".cts": ts.ScriptKind.TS,
	".tsx": ts.ScriptKind.TSX,
	".js": ts.ScriptKind.JS,
	".mjs": ts.ScriptKind.JS,
	".cjs": ts.ScriptKind.JS,
	".jsx": ts.ScriptKind.JSX,
};
const file = ts.createSourceFile(
	path,
	source,
	ts.ScriptTarget.Latest,
	true,
	scriptKinds[extname(path)] ?? ts.ScriptKind.TS,
);
const comments = new Map();
const DIRECTIVE =
	/^(?:@ts-|biome-ignore|eslint-|eslint |prettier-ignore|istanbul |c8 |v8 |@vite-ignore|webpack[A-Z]|[@#]__PURE__|[@#]__NO_SIDE_EFFECTS__|@jsx|@license|@preserve|#region|#endregion|<reference )/;

const isKept = (text) => {
	if (text.startsWith("/**") && text.length > 4) {
		return true;
	}

	if (text.startsWith("///") || text.startsWith("/*!")) {
		return true;
	}

	return DIRECTIVE.test(text.replace(/^\/[/*]\s*/, "").replace(/^\*+\s*/, ""));
};

const collect = (node) => {
	if (node.kind === ts.SyntaxKind.JsxText) {
		return;
	}

	for (const range of [
		...(ts.getLeadingCommentRanges(source, node.pos) ?? []),
		...(ts.getTrailingCommentRanges(source, node.end) ?? []),
	]) {
		if (!isKept(source.slice(range.pos, range.end))) {
			comments.set(range.pos, range.end);
		}
	}

	for (const child of node.getChildren(file)) {
		collect(child);
	}
};

collect(file);

let stripped = "";
let cursor = 0;

for (const [start, end] of [...comments].sort(
	([first], [second]) => first - second,
)) {
	if (start < cursor) {
		continue;
	}

	stripped +=
		source.slice(cursor, start) +
		source.slice(start, end).replace(/[^\n]/g, "");
	cursor = end;
}

stripped += source.slice(cursor);

const originalLines = source.split("\n");
const output = stripped
	.split("\n")
	.map((line) => line.trimEnd())
	.filter(
		(line, index) =>
			line.trim() !== "" || (originalLines[index] ?? "").trim() === "",
	)
	.join("\n");

process.stdout.write(output);
