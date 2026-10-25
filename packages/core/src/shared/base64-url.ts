/** Bytes as base64url without padding, the alphabet of every sealed value and record seal. */
export const toBase64Url = (bytes: Uint8Array): string => {
	return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replaceAll("=", "");
};

/** The bytes of base64url text; throws on text that is not base64. */
export const fromBase64Url = (text: string): Uint8Array<ArrayBuffer> => {
	return Uint8Array.from(
		atob(text.replaceAll("-", "+").replaceAll("_", "/")),
		(character) => character.charCodeAt(0),
	);
};
