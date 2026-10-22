import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { flows, GROUPS } from "./flows/index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPOSITORY = resolve(HERE, "../..");
const OUTPUT = join(HERE, "flow-data.js");
const AUDIT_FILE = "packages/core/src/audit.ts";
const PORT_FILES = {
	IdentityStore: "packages/core/src/identity/identity-store.ts",
	EpochStore: "packages/core/src/session-tokens/epoch-store.ts",
	TokenStore: "packages/core/src/tokens/token-store.ts",
	MeterStore: "packages/core/src/meter/meter-store.ts",
	OutboxStore: "packages/core/src/outbox/outbox-store.ts",
};
const START_KINDS = new Set(["start"]);
const END_KINDS = new Set(["end-ok", "end-fail", "end-wait"]);
const KINDS = new Set([
	...START_KINDS,
	...END_KINDS,
	"step",
	"decision",
	"port",
	"jump",
	"adapter",
]);
const EDGE_KINDS = new Set(["ok", "fail", "branch"]);
const EVENT_NAME = /\b[a-z]+\.[a-z]+\b/g;

const read = (file) => readFileSync(join(REPOSITORY, file), "utf8");

const lineOf = (file, pattern, problems, where) => {
	if (!existsSync(join(REPOSITORY, file))) {
		problems.push(`${where}: file ${file} does not exist`);
		return undefined;
	}

	const index = read(file)
		.split("\n")
		.findIndex((line) => line.includes(pattern));

	if (index === -1) {
		problems.push(`${where}: "${pattern}" is not in ${file}`);
		return undefined;
	}

	return index + 1;
};

const auditEvents = () => {
	const text = read(AUDIT_FILE);
	const block = text.slice(
		text.indexOf("export const AUDIT_EVENTS"),
		text.indexOf("} as const", text.indexOf("export const AUDIT_EVENTS")),
	);

	return [...block.matchAll(/"([a-z]+\.[a-z]+)"/g)].map((match) => match[1]);
};

const hasCycle = (nodes, edges) => {
	const next = new Map(nodes.map((item) => [item.id, []]));

	for (const { from, to } of edges) {
		next.get(from)?.push(to);
	}

	const state = new Map();
	const visit = (id) => {
		if (state.get(id) === "done") return false;
		if (state.get(id) === "open") return true;
		state.set(id, "open");

		for (const target of next.get(id) ?? []) {
			if (visit(target)) return true;
		}

		state.set(id, "done");

		return false;
	};

	return nodes.some((item) => visit(item.id));
};

const checkFlow = (item, problems, allFlows) => {
	const ids = new Set();

	for (const entry of item.nodes) {
		if (ids.has(entry.id))
			problems.push(`${item.id}: node ${entry.id} is listed twice`);
		ids.add(entry.id);

		if (!KINDS.has(entry.kind))
			problems.push(`${item.id}.${entry.id}: unknown kind ${entry.kind}`);
	}

	for (const entry of item.edges) {
		if (!ids.has(entry.from))
			problems.push(`${item.id}: edge from unknown node ${entry.from}`);
		if (!ids.has(entry.to))
			problems.push(`${item.id}: edge to unknown node ${entry.to}`);
		if (!EDGE_KINDS.has(entry.kind))
			problems.push(`${item.id}: unknown edge kind ${entry.kind}`);
	}

	if (!item.nodes.some((entry) => START_KINDS.has(entry.kind))) {
		problems.push(`${item.id}: no start node`);
	}

	if (
		!item.nodes.some((entry) => END_KINDS.has(entry.kind)) &&
		item.id !== "map"
	) {
		problems.push(`${item.id}: no end node`);
	}

	const reached = new Set(
		item.nodes
			.filter((entry) => START_KINDS.has(entry.kind))
			.map((entry) => entry.id),
	);
	let grew = true;

	while (grew) {
		grew = false;

		for (const { from, to } of item.edges) {
			if (reached.has(from) && !reached.has(to)) {
				reached.add(to);
				grew = true;
			}
		}
	}

	for (const entry of item.nodes) {
		if (!reached.has(entry.id))
			problems.push(`${item.id}.${entry.id}: not reachable from a start`);
		if (
			END_KINDS.has(entry.kind) &&
			item.edges.some((edge) => edge.from === entry.id)
		) {
			problems.push(`${item.id}.${entry.id}: an end node has an outgoing edge`);
		}
	}

	if (hasCycle(item.nodes, item.edges))
		problems.push(`${item.id}: the flow has a cycle`);

	const layerOfNode = new Map(
		item.nodes.map((entry) => [entry.id, entry.layer]),
	);

	for (const entry of item.edges) {
		const from = layerOfNode.get(entry.from);
		const to = layerOfNode.get(entry.to);

		if (from !== undefined && to !== undefined && from >= to) {
			problems.push(
				`${item.id}: edge ${entry.from} -> ${entry.to} does not go down a layer`,
			);
		}
	}

	for (const entry of item.nodes) {
		if (entry.jump === undefined) continue;

		const target = allFlows.find((other) => other.id === entry.jump.flow);

		if (target === undefined) {
			problems.push(
				`${item.id}.${entry.id}: jump to unknown flow ${entry.jump.flow}`,
			);
		} else if (!target.nodes.some((other) => other.id === entry.jump.node)) {
			problems.push(
				`${item.id}.${entry.id}: jump to unknown node ${entry.jump.flow}.${entry.jump.node}`,
			);
		}
	}
};

/**
 * Checks the flows against the code and resolves each function to a line.
 * It returns the data for the page and the list of problems; a function that
 * moved away, a port method that does not exist, or an audit event that no
 * flow shows is a problem, so the diagram cannot quietly go stale.
 */
export const buildFlowData = () => {
	const problems = [];
	const events = auditEvents();
	const shown = new Set();
	const resolved = flows.map((item) => {
		checkFlow(item, problems, flows);

		return {
			...item,
			nodes: item.nodes.map((entry) => {
				const where = `${item.id}.${entry.id}`;
				let source;

				if (entry.where !== undefined) {
					const [file, pattern] = entry.where.split("#");
					const line = lineOf(file, pattern, problems, where);

					source = line === undefined ? undefined : { file, line };
				}

				if (entry.port !== undefined) {
					const store = entry.port.match(/^(\w+Store)\.(\w+)/);

					if (store === null) {
						problems.push(
							`${where}: port "${entry.port}" must look like Store.method(...)`,
						);
					} else if (!(store[1] in PORT_FILES)) {
						problems.push(`${where}: unknown port ${store[1]}`);
					} else if (!read(PORT_FILES[store[1]]).includes(`${store[2]}(`)) {
						problems.push(`${where}: ${store[1]} has no method ${store[2]}`);
					}
				}

				for (const name of (entry.audit ?? "").match(EVENT_NAME) ?? []) {
					if (events.includes(name)) {
						shown.add(name);
					} else if (
						/^(identity|policy|proof|session|seal|token|meter|signin|authorize|delegation)\./.test(
							name,
						)
					) {
						problems.push(`${where}: unknown audit event ${name}`);
					}
				}

				const { where: _where, ...rest } = entry;

				return source === undefined ? rest : { ...rest, source };
			}),
		};
	});

	for (const name of events) {
		if (!shown.has(name))
			problems.push(`audit event ${name} is not shown in any flow`);
	}

	return {
		data: {
			groups: GROUPS,
			events,
			ports: Object.keys(PORT_FILES),
			flows: resolved,
		},
		problems,
	};
};

export const serialize = (data) =>
	`window.FLOW_DATA = ${JSON.stringify(data, null, "\t")};\n`;

if (
	process.argv[1] !== undefined &&
	import.meta.url === pathToFileURL(process.argv[1]).href
) {
	const { data, problems } = buildFlowData();

	if (problems.length > 0) {
		console.error(problems.map((problem) => `- ${problem}`).join("\n"));
		process.exitCode = 1;
	} else {
		writeFileSync(OUTPUT, serialize(data));
		console.log(`flow-data.js: ${data.flows.length} flows`);
	}
}
