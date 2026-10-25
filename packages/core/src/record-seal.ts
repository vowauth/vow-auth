import {
	parseSealed,
	requireValidSecrets,
	type SecretVersion,
} from "./sealer.js";
import { fromBase64Url, toBase64Url } from "./shared/base64-url.js";

const RECORD_KEY_LABEL = "vow-auth/record/v1/";

/** One field of a sealed record, in the order the record kind fixes; a number is a safe integer. */
export type RecordField = string | number | boolean | null;

/**
 * What a seal says about a record: it matches the fields under the newest
 * secret, it matches under an older one and should be sealed again, or it
 * does not match at all.
 */
export type RecordCheck = "valid" | "stale" | "invalid";

/**
 * Seals the records the engine keeps, so a row written past the engine, or
 * one whose fields were changed, is told apart from the engine's own.
 */
export type RecordSeal = {
	seal(fields: readonly RecordField[]): Promise<string>;
	check(fields: readonly RecordField[], seal: string): Promise<RecordCheck>;
};

const encoder = new TextEncoder();

const deriveRecordKey = async (value: string): Promise<CryptoKey> => {
	const secret = await crypto.subtle.importKey(
		"raw",
		encoder.encode(value),
		"HKDF",
		false,
		["deriveKey"],
	);

	return crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(0),
			info: encoder.encode(RECORD_KEY_LABEL),
		},
		secret,
		{ name: "HMAC", hash: "SHA-256", length: 256 },
		false,
		["sign", "verify"],
	);
};

/**
 * Creates the record seal: HMAC-SHA-256 of the fields as JSON, with a key
 * derived by HKDF from each secret under a label of its own, apart from the
 * keys of sealed values and of factors, so nothing sealed elsewhere passes
 * as a record. A seal is `<secret version>.<base64url>`; the newest secret
 * seals, every listed one checks, and a seal of a version no longer listed
 * does not match.
 */
export function createRecordSeal(options: {
	readonly secrets: readonly SecretVersion[];
}): RecordSeal {
	const current = requireValidSecrets(options.secrets);
	const keys = new Map(
		options.secrets.map((secret) => [
			secret.version,
			deriveRecordKey(secret.value),
		]),
	);

	const bytesOf = (fields: readonly RecordField[]) =>
		encoder.encode(JSON.stringify(fields));

	return {
		async seal(fields) {
			const key = await keys.get(current.version);

			if (key === undefined) {
				throw new Error("The newest secret has no record key");
			}

			const mac = await crypto.subtle.sign("HMAC", key, bytesOf(fields));

			return `${current.version}.${toBase64Url(new Uint8Array(mac))}`;
		},
		async check(fields, seal) {
			const parsed = typeof seal === "string" ? parseSealed(seal) : undefined;
			const key = parsed === undefined ? undefined : keys.get(parsed.version);

			if (parsed === undefined || key === undefined) {
				return "invalid";
			}

			let matches: boolean;

			try {
				matches = await crypto.subtle.verify(
					"HMAC",
					await key,
					fromBase64Url(parsed.body),
					bytesOf(fields),
				);
			} catch {
				return "invalid";
			}

			if (!matches) {
				return "invalid";
			}

			return parsed.version === current.version ? "valid" : "stale";
		},
	};
}
