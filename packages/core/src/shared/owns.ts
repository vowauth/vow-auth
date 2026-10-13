export const owns = (node: object, key: PropertyKey): boolean => {
	return Object.hasOwn(node, key);
};
