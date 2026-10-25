import { SECRET_BYTES } from "./constants.js";

const HEX_BYTE_TABLE: readonly string[] = Array.from(
	{ length: 256 },
	(_, byte) => byte.toString(16).padStart(2, "0"),
);

const toHex = (bytes: Uint8Array): string => {
	return Array.from(bytes, (byte) => HEX_BYTE_TABLE[byte]).join("");
};

const ID_BYTES = 16;

/** An id the engine chooses: the prefix and 128 random bits in hex, such as `acc_3f…`. */
export const generateId = (prefix: string): string => {
	return prefix + toHex(crypto.getRandomValues(new Uint8Array(ID_BYTES)));
};

export const generateSecret = (): string => {
	return toHex(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
};

export const hashSecret = async (secret: string): Promise<string> => {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(secret),
	);

	return toHex(new Uint8Array(digest));
};
