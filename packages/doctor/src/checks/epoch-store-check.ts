import type { Check } from "../finding.js";
import {
	inParallel,
	PROBE_TIME_TO_LIVE_MILLISECONDS,
	probeId,
} from "../probe.js";

const PARALLEL_REVOCATIONS = 16;

export const epochStoreCheck: Check = {
	id: "epoch-store-stamp-not-rising",
	title: "The epoch store raises a stamp on every revocation",
	async run({ options }) {
		const store = options.epochs;
		const key = probeId("epoch");
		const first = await store.revoke(key, PROBE_TIME_TO_LIVE_MILLISECONDS);
		const second = await store.revoke(key, PROBE_TIME_TO_LIVE_MILLISECONDS);
		const parallel = await inParallel(PARALLEL_REVOCATIONS, () =>
			store.revoke(key, PROBE_TIME_TO_LIVE_MILLISECONDS),
		);
		const { stamps } = await store.read([key]);
		const highest = Math.max(first, second, ...parallel);
		const sequentialRises = second > first;
		const parallelDistinct = new Set(parallel).size === parallel.length;
		const readSeesLast = (stamps[0] ?? 0) >= highest;

		if (sequentialRises && parallelDistinct && readSeesLast) {
			return [];
		}

		const detail = !sequentialRises
			? `two revocations in a row returned ${first} and ${second}`
			: !parallelDistinct
				? `${PARALLEL_REVOCATIONS} parallel revocations returned only ${new Set(parallel).size} different stamps`
				: `a read after the revocations returned ${stamps[0]}, below ${highest}`;

		return [
			{
				id: "epoch-store-stamp-not-rising",
				level: "error",
				title: `A revocation does not always raise the stamp: ${detail}`,
				scenario: [
					"Sign in; the token carries the stamp the store showed when it was issued.",
					"Revoke the session (log out, or delete the user).",
					`The store gives the revocation a stamp that is not above the token's (${detail}), so the token still counts as newer and verifies: a revoked session stays alive.`,
				],
				fix: "Make revoke one atomic step that sets the key to max(current + 1, now) by the store's own clock and returns it (a Redis Lua script, or SQL UPDATE ... RETURNING), and make read see every completed revoke. Run epochStoreContract of @vow-auth/store-contracts against the adapter.",
			},
		];
	},
};
