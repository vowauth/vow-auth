const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BITS_PER_CHARACTER = 5;
const BITS_PER_BYTE = 8;

/** Writes bytes as RFC 4648 base32 without padding, the form authenticator apps take. */
export const encodeBase32 = (bytes: Uint8Array): string => {
	let output = "";
	let buffer = 0;
	let bufferedBits = 0;

	for (const byte of bytes) {
		buffer = (buffer << BITS_PER_BYTE) | byte;
		bufferedBits += BITS_PER_BYTE;

		while (bufferedBits >= BITS_PER_CHARACTER) {
			bufferedBits -= BITS_PER_CHARACTER;
			output += ALPHABET[(buffer >>> bufferedBits) & 0b11111];
		}

		buffer &= (1 << bufferedBits) - 1;
	}

	if (bufferedBits > 0) {
		output +=
			ALPHABET[(buffer << (BITS_PER_CHARACTER - bufferedBits)) & 0b11111];
	}

	return output;
};

/** Reads RFC 4648 base32 without padding; `undefined` for any other character. */
export const decodeBase32 = (
	text: string,
): Uint8Array<ArrayBuffer> | undefined => {
	const bytes: number[] = [];
	let buffer = 0;
	let bufferedBits = 0;

	for (const character of text) {
		const value = ALPHABET.indexOf(character);

		if (value === -1) {
			return undefined;
		}

		buffer = (buffer << BITS_PER_CHARACTER) | value;
		bufferedBits += BITS_PER_CHARACTER;

		if (bufferedBits >= BITS_PER_BYTE) {
			bufferedBits -= BITS_PER_BYTE;
			bytes.push((buffer >>> bufferedBits) & 0xff);
			buffer &= (1 << bufferedBits) - 1;
		}
	}

	return Uint8Array.from(bytes);
};
