import type { Check } from "../finding.js";
import {
	inParallel,
	PARALLEL_CALLS,
	PROBE_TIME_TO_LIVE_MILLISECONDS,
	probeId,
} from "../probe.js";

export const tokenStoreCheck: Check = {
	id: "token-store-not-atomic",
	title: "The token store hands a one-time record to one taker",
	async run({ options }) {
		const store = options.tokenStore;
		const hash = probeId("token");

		await store.put(hash, {
			purpose: "doctor",
			payload: {},
			expiresAtMilliseconds: Date.now() + PROBE_TIME_TO_LIVE_MILLISECONDS,
		});

		const results = await inParallel(PARALLEL_CALLS, () => store.take(hash));
		const winners = results.filter((record) => record !== undefined).length;

		if (winners === 1) {
			return [];
		}

		if (winners === 0) {
			return [
				{
					id: "token-store-loses-records",
					level: "error",
					title: "The token store lost a record it had accepted",
					scenario: [
						"Request a sign-in link; the store accepts the record.",
						"Open the link: no instance can take the record, so every valid link is refused.",
					],
					fix: "A completed put must be visible to take on every instance; use a strongly consistent store, not an eventually consistent one such as Workers KV.",
				},
			];
		}

		return [
			{
				id: "token-store-not-atomic",
				level: "error",
				title: `${winners} of ${PARALLEL_CALLS} parallel takes received one record`,
				scenario: [
					"Request a sign-in link for an account you own.",
					`Open the link in ${PARALLEL_CALLS} requests at the same moment.`,
					`${winners} requests redeem the one-time link and each gets a session: a one-time secret works ${winners} times.`,
				],
				fix: "Make take one atomic step: Redis GETDEL, SQL DELETE ... RETURNING, or a Lua script. A read followed by a delete is not atomic. Run tokenStoreContract of @vow-auth/store-contracts against the adapter.",
			},
		];
	},
};
