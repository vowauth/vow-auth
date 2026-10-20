import { owns } from "./owns.js";

export const own = <Source extends object, Key extends keyof Source & string>(
	source: Source,
	key: Key,
): Source[Key] | undefined => {
	if (!owns(source, key)) {
		return undefined;
	}

	return source[key];
};
