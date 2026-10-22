import type { Check } from "../finding.js";
import { inParallel, PROBE_WINDOW_MILLISECONDS, probeId } from "../probe.js";

const LIMIT = 10;
const PARALLEL_REQUESTS = 40;

export const meterStoreCheck: Check = {
	id: "meter-store-over-allows",
	title: "The meter store holds a limit against parallel requests",
	async run({ options }) {
		const key = probeId("meter");
		const results = await inParallel(PARALLEL_REQUESTS, () =>
			options.meterStore.consume({
				key,
				cost: 1,
				limit: LIMIT,
				windowMilliseconds: PROBE_WINDOW_MILLISECONDS,
			}),
		);
		const allowed = results.filter((result) => result.allowed).length;

		if (allowed <= LIMIT) {
			return [];
		}

		return [
			{
				id: "meter-store-over-allows",
				level: "error",
				title: `${allowed} of ${PARALLEL_REQUESTS} parallel requests passed a limit of ${LIMIT}`,
				scenario: [
					`Find an endpoint limited to ${LIMIT} requests per window, such as an email link or a code attempt.`,
					`Send ${PARALLEL_REQUESTS} requests at the same moment.`,
					`${allowed} are counted as allowed instead of ${LIMIT}: the limit does not hold against parallel requests, so guessing and mail bombing are not slowed down.`,
				],
				fix: "Make consume one atomic step by the store's own clock (a Redis Lua script, or one SQL statement). Run meterStoreContract of @vow-auth/store-contracts against the adapter.",
			},
		];
	},
};
