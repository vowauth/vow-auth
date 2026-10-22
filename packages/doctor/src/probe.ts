export const PARALLEL_CALLS = 32;
export const PROBE_TIME_TO_LIVE_MILLISECONDS = 60_000;
export const PROBE_WINDOW_MILLISECONDS = 60_000;

export const probeId = (name: string): string => {
	return `vow-doctor-${name}-${crypto.randomUUID()}`;
};

export const inParallel = <Value>(
	calls: number,
	call: (index: number) => Promise<Value>,
): Promise<Value[]> => {
	return Promise.all(Array.from({ length: calls }, (_, index) => call(index)));
};
