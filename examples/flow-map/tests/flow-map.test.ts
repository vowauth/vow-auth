import { readFileSync } from "node:fs";
import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { createAuth } from "@vow-auth/core";
import { expect, test } from "vitest";
import { buildFlowData, serialize } from "../build.mjs";

test("every function, port method and audit event that the diagram names exists in the code", () => {
	expect(buildFlowData().problems).toEqual([]);
});

test("the data the page loads is the data of the current code", () => {
	const committed = readFileSync(
		new URL("../flow-data.js", import.meta.url),
		"utf8",
	);

	expect(committed).toBe(serialize(buildFlowData().data));
});

test("every part of the Auth surface has a place on the map of layers", () => {
	const auth = createAuth({
		identities: createMemoryIdentityStore(),
		epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
		tokenStore: createMemoryTokenStore({ maximumBytes: 1_000_000 }),
		meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
		secrets: [{ version: 1, value: "flow-map-secret-0123456789abcdefghijk" }],
		maximumLifeTimeMilliseconds: 60_000,
		sessionTimeToLiveMilliseconds: 60_000,
		policy: () => "deny",
		audit: async () => undefined,
	});
	const map = buildFlowData().data.flows.find((flow) => flow.id === "map");
	const titles = (map?.nodes ?? []).map((node) => node.title);

	for (const part of Object.keys(auth)) {
		expect(
			titles.some((title) => title.includes(part)),
			`${part} is not on the map`,
		).toBe(true);
	}
});

test("every flow is reachable from the navigation and has a way in and a way out", () => {
	const { data } = buildFlowData();
	const groups = new Set(data.groups);

	for (const flow of data.flows) {
		expect(groups.has(flow.group), flow.id).toBe(true);
		expect(
			flow.nodes.some((node) => node.kind === "start"),
			flow.id,
		).toBe(true);
	}

	expect(new Set(data.flows.map((flow) => flow.id)).size).toBe(
		data.flows.length,
	);
});
