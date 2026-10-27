import {
	parseSealed,
	requireValidSecrets,
	type SecretVersion,
} from "./sealer.js";
import { fromBase64Url, toBase64Url } from "./shared/base64-url.js";

const BOX_KEY_LABEL = "vow-auth/box/v1/";
const SALT_BYTES = 16;
const INITIALIZATION_VECTOR_BYTES = 12;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Keeps secrets that the engine stores and must read back, such as the
 * private signing keys of tenants. Unlike a sealed value, a boxed one does not
 * expire.
 */
export type SecretBox = {
	seal(plaintext: string, context: readonly string[]): Promise<string>;
	/** The plaintext, or `undefined` when the value is malformed, of another context, of an unlisted secret or changed. */
	open(sealed: string, context: readonly string[]): Promise<string | undefined>;
};

/**
 * Creates the secret box: AES-256-GCM with a key derived by HKDF-SHA-256 from
 * the secret, a random salt and the context, under a label of its own, so a
 * value boxed for one context opens in no other and nothing sealed elsewhere
 * opens here. The format is the sealer's, `<secret version>.<base64url(salt ‖
 * IV ‖ ciphertext)>`; the newest secret boxes and every listed one opens.
 */
export function createSecretBox(options: {
	readonly secrets: readonly SecretVersion[];
}): SecretBox {
	const current = requireValidSecrets(options.secrets);
	const secretKeys = new Map(
		options.secrets.map((secret) => [
			secret.version,
			crypto.subtle.importKey(
				"raw",
				encoder.encode(secret.value),
				"HKDF",
				false,
				["deriveKey"],
			),
		]),
	);

	const keyFor = async (
		secretKey: Promise<CryptoKey>,
		salt: Uint8Array<ArrayBuffer>,
		context: readonly string[],
	): Promise<CryptoKey> =>
		crypto.subtle.deriveKey(
			{
				name: "HKDF",
				hash: "SHA-256",
				salt,
				info: encoder.encode(BOX_KEY_LABEL + JSON.stringify(context)),
			},
			await secretKey,
			{ name: "AES-GCM", length: 256 },
			false,
			["encrypt", "decrypt"],
		);

	return {
		async seal(plaintext, context) {
			const secretKey = secretKeys.get(current.version);

			if (secretKey === undefined) {
				throw new Error("The newest secret has no key");
			}

			const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
			const initializationVector = crypto.getRandomValues(
				new Uint8Array(INITIALIZATION_VECTOR_BYTES),
			);
			const ciphertext = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: initializationVector },
				await keyFor(secretKey, salt, context),
				encoder.encode(plaintext),
			);

			return `${current.version}.${toBase64Url(
				new Uint8Array([
					...salt,
					...initializationVector,
					...new Uint8Array(ciphertext),
				]),
			)}`;
		},
		async open(sealed, context) {
			const parsed = parseSealed(sealed);
			const secretKey =
				parsed === undefined ? undefined : secretKeys.get(parsed.version);

			if (parsed === undefined || secretKey === undefined) {
				return undefined;
			}

			try {
				const bytes = fromBase64Url(parsed.body);
				const plaintext = await crypto.subtle.decrypt(
					{
						name: "AES-GCM",
						iv: bytes.slice(
							SALT_BYTES,
							SALT_BYTES + INITIALIZATION_VECTOR_BYTES,
						),
					},
					await keyFor(secretKey, bytes.slice(0, SALT_BYTES), context),
					bytes.slice(SALT_BYTES + INITIALIZATION_VECTOR_BYTES),
				);

				return decoder.decode(plaintext);
			} catch {
				return undefined;
			}
		},
	};
}
