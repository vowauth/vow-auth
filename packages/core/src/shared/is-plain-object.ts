import { owns } from "./owns.js";

export type PlainObject = Record<string, unknown>;

export const isPlainObject = (value: unknown): value is PlainObject => {
	if (typeof value !== "object" || value === null) {
		return false;
	}

	const constructorValue: unknown = value.constructor;

	if (typeof constructorValue !== "function") {
		return true;
	}

	const prototype: unknown = constructorValue.prototype;

	if (typeof prototype !== "object" || prototype === null) {
		return false;
	}

	return owns(prototype, "isPrototypeOf");
};
