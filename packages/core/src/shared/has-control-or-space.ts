const INVISIBLE_OR_SPACE = /[\p{C}\p{Z}]/u;

export const hasControlOrSpace = (text: string): boolean => {
	return INVISIBLE_OR_SPACE.test(text);
};
