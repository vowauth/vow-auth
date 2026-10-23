import { encodeBase32 } from "./base32.js";

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_BYTES = 16;
const GROUP_LENGTH = 4;
const SEPARATOR = "-";
const IGNORED = /[\s-]/g;
const HEX_RADIX = 16;
const HEX_WIDTH = 2;

/** Writes a code the way the person will read it back: groups of four joined by dashes. */
const grouped = (text: string): string => {
	const groups: string[] = [];

	for (let index = 0; index < text.length; index += GROUP_LENGTH) {
		groups.push(text.slice(index, index + GROUP_LENGTH));
	}

	return groups.join(SEPARATOR);
};

/** What is stored and compared: case, spaces and dashes do not matter. */
const normalizeBackupCode = (code: string): string =>
	code.replace(IGNORED, "").toUpperCase();

/** SHA-256 of the normalized code, in hex. The codes carry 128 bits, above the 112 bits at which NIST SP 800-63B-4 allows a plain hash. */
export const hashBackupCode = async (code: string): Promise<string> => {
	const digest = new Uint8Array(
		await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(normalizeBackupCode(code)),
		),
	);

	return Array.from(digest, (byte) =>
		byte.toString(HEX_RADIX).padStart(HEX_WIDTH, "0"),
	).join("");
};

/** Makes a new set of codes from the random generator of the platform. */
export const generateBackupCodes = (): readonly string[] =>
	Array.from({ length: BACKUP_CODE_COUNT }, () =>
		grouped(
			encodeBase32(crypto.getRandomValues(new Uint8Array(BACKUP_CODE_BYTES))),
		),
	);
