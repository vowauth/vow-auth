/** The two counters of one key: the interval they belong to, its count, and the count of the interval before. */
export type SlidingWindowState = {
	readonly windowMilliseconds: number;
	readonly index: number;
	readonly current: number;
	readonly previous: number;
};

/** One request to decide. `state` is what the store holds for the key, if anything. */
export type SlidingWindowInput = {
	readonly state: SlidingWindowState | undefined;
	readonly nowMilliseconds: number;
	readonly windowMilliseconds: number;
	readonly limit: number;
	readonly cost: number;
};

/**
 * The verdict, the state to keep and the numbers to report. `state` already
 * holds the cost when the request is allowed and is the rolled state without
 * it when it is not: a store keeps it only for an allowed request.
 * `estimate` is the rate after counting an allowed request, and the rate as it
 * stands for a refused one. `retryAtMilliseconds` is the earliest moment the
 * same request would be allowed if nothing else were counted; for an allowed
 * request it is the moment the key reads zero again.
 */
export type SlidingWindowOutcome = {
	readonly allowed: boolean;
	readonly state: SlidingWindowState;
	readonly estimate: number;
	readonly retryAtMilliseconds: number;
};

const TOLERANCE = 1e-9;

const roll = (
	state: SlidingWindowState | undefined,
	index: number,
	windowMilliseconds: number,
): SlidingWindowState => {
	if (state === undefined || state.windowMilliseconds !== windowMilliseconds) {
		return { windowMilliseconds, index, current: 0, previous: 0 };
	}

	if (state.index >= index) {
		return state;
	}

	return state.index === index - 1
		? { windowMilliseconds, index, current: 0, previous: state.current }
		: { windowMilliseconds, index, current: 0, previous: 0 };
};

const earliestRetry = (rolled: SlidingWindowState, room: number): number => {
	const { windowMilliseconds, current, previous } = rolled;
	const intervalStart = rolled.index * windowMilliseconds;

	if (current <= room && previous > 0) {
		const elapsed = Math.max(
			0,
			windowMilliseconds - (windowMilliseconds * (room - current)) / previous,
		);

		if (elapsed < windowMilliseconds) {
			return intervalStart + elapsed;
		}
	}

	const nextStart = intervalStart + windowMilliseconds;

	return current > room
		? nextStart + windowMilliseconds - (windowMilliseconds * room) / current
		: nextStart;
};

/**
 * Decides one request with the sliding window approximation of Cloudflare's
 * rate limiting. Time is cut into intervals of `windowMilliseconds`, aligned to
 * the epoch, and a key keeps two counters: the interval it last counted in and
 * the one before. At `elapsed` into the current interval the rate is
 * `previous * (window - elapsed) / window + current`; a request with `cost` is
 * allowed when `rate + cost <= limit`. The rate falls steadily as the previous
 * interval fades, so there is no boundary at which a full limit passes twice.
 * It assumes the previous interval was even, hence an approximation. A key
 * whose window length changes starts again from zero. A clock that moved back
 * keeps the newer interval and counts it from its start, which is the
 * stricter reading.
 */
export const slidingWindow = (
	input: SlidingWindowInput,
): SlidingWindowOutcome => {
	const { nowMilliseconds, windowMilliseconds, limit, cost } = input;
	const index = Math.floor(nowMilliseconds / windowMilliseconds);
	const rolled = roll(input.state, index, windowMilliseconds);
	const elapsed = Math.min(
		windowMilliseconds,
		Math.max(0, nowMilliseconds - rolled.index * windowMilliseconds),
	);
	const estimate =
		(rolled.previous * (windowMilliseconds - elapsed)) / windowMilliseconds +
		rolled.current;

	if (estimate + cost > limit + TOLERANCE) {
		return {
			allowed: false,
			state: rolled,
			estimate,
			retryAtMilliseconds: Math.ceil(earliestRetry(rolled, limit - cost)),
		};
	}

	return {
		allowed: true,
		state: { ...rolled, current: rolled.current + cost },
		estimate: estimate + cost,
		retryAtMilliseconds: (rolled.index + 2) * windowMilliseconds,
	};
};
