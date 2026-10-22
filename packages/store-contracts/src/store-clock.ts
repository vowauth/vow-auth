/**
 * The clock a store runs by, as the contract tests can use it. A store that
 * reads the machine clock is driven with fake timers; a store that reads the
 * clock of a server (Redis `TIME`) can only be waited for.
 */
export type StoreClock = {
	/** The store's current Unix time in milliseconds. */
	now(): Promise<number>;
	/** Lets the store's time pass by at least this many milliseconds. */
	advance(milliseconds: number): Promise<void>;
	/** Sets the store's time exactly. Only for a clock that can be controlled. */
	set?(milliseconds: number): void;
};
