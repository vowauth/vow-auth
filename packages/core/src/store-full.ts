const STORE_FULL_CODE = "store-full";

/**
 * The error a store throws when it has no room for one more record and will
 * not drop a live one to make it. A caller that needs to tell this apart from
 * a failing store checks it with `isStoreFullError`.
 */
export const storeFullError = (message: string): Error => {
	return Object.assign(new Error(message), { code: STORE_FULL_CODE });
};

/** Whether an error says that a store was full. */
export const isStoreFullError = (error: unknown): boolean => {
	return (
		typeof error === "object" &&
		error !== null &&
		Reflect.get(error, "code") === STORE_FULL_CODE
	);
};
