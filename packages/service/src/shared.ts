export const isRecord = (value: unknown): value is Record<string, unknown> => {
	return typeof value === "object" && value !== null && !Array.isArray(value);
};

export const field = (value: unknown, key: string): unknown => {
	return isRecord(value) && Object.hasOwn(value, key)
		? Reflect.get(value, key)
		: undefined;
};

export const hasOnlyKeys = (
	value: Record<string, unknown>,
	allowed: readonly string[],
): boolean => {
	return Object.keys(value).every((key) => allowed.includes(key));
};

export const isString = (value: unknown): value is string => {
	return typeof value === "string";
};

export const isFiniteNumber = (value: unknown): value is number => {
	return typeof value === "number" && Number.isFinite(value);
};
