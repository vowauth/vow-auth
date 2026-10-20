const ENTRY_OVERHEAD_BYTES = 256;
const BYTES_PER_CHARACTER = 2;

export const estimateBytes = (characters: number): number => {
	return ENTRY_OVERHEAD_BYTES + BYTES_PER_CHARACTER * characters;
};
