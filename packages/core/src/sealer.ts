import { fail, type Result, succeed } from "./result.js";
import { own } from "./shared/own.js";

/** One version of the server secret. */
export type SecretVersion = {
	readonly version: number;
	readonly value: string;
};

/** Options for creating the sealer. */
export type SealerOptions = {
	/**
	 * Server secrets, newest first. The first one seals; every listed one
	 * unseals, so values sealed before a rotation stay valid until they expire
	 * or their secret is removed. Each value must be random and at least 32
	 * characters long, for example `openssl rand -base64 32`.
	 */
	readonly secrets: readonly SecretVersion[];
};

/** Parameters of a value to seal. */
export type SealInput = {
	readonly purpose: string;
	readonly payload?: Readonly<Record<string, string>>;
	readonly timeToLiveMilliseconds: number;
};

/**
 * Encrypted, authenticated, purpose-bound and expiring values that need no
 * server state, such as OAuth state in a cookie. Unlike tokens, a sealed value
 * is not one-time: it unseals again and again until it expires.
 */
export type Sealer = {
	seal(input: SealInput): Promise<string>;
	unseal(
		sealed: string,
		purpose: string,
	): Promise<Result<Readonly<Record<string, string>>>>;
};

type SealedContents = {
	readonly payload: Readonly<Record<string, string>>;
	readonly expiresAtMilliseconds: number;
};

const MINIMUM_SECRET_LENGTH = 32;
const SALT_BYTES = 16;
const INITIALIZATION_VECTOR_BYTES = 12;
const KEY_DERIVATION_LABEL = "vow-auth/seal/v1/";
const SEALED_PATTERN = /^(0|[1-9][0-9]{0,8})\.([A-Za-z0-9_-]+)$/;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const toBase64Url = (bytes: Uint8Array): string => {
	return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replaceAll("=", "");
};

const fromBase64Url = (text: string): Uint8Array<ArrayBuffer> => {
	return Uint8Array.from(
		atob(text.replaceAll("-", "+").replaceAll("_", "/")),
		(character) => character.charCodeAt(0),
	);
};

const randomBytes = (length: number): Uint8Array<ArrayBuffer> => {
	return crypto.getRandomValues(new Uint8Array(length));
};

const deriveMessageKey = (
	secretKey: CryptoKey,
	salt: Uint8Array<ArrayBuffer>,
	purpose: string,
): Promise<CryptoKey> => {
	return crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt,
			info: encoder.encode(KEY_DERIVATION_LABEL + purpose),
		},
		secretKey,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
};

const importSecret = (value: string): Promise<CryptoKey> => {
	return crypto.subtle.importKey("raw", encoder.encode(value), "HKDF", false, [
		"deriveKey",
	]);
};

const requireValidSecrets = (
	secrets: readonly SecretVersion[],
): SecretVersion => {
	const [current] = secrets;

	if (current === undefined) {
		throw new RangeError("secrets must contain at least one secret");
	}

	const versions = new Set<number>();

	for (const secret of secrets) {
		if (!Number.isSafeInteger(secret.version) || secret.version < 0) {
			throw new RangeError("A secret version must be a non-negative integer");
		}

		if (versions.has(secret.version)) {
			throw new RangeError(`Secret version ${secret.version} is listed twice`);
		}

		if (secret.value.length < MINIMUM_SECRET_LENGTH) {
			throw new RangeError(
				`Secret version ${secret.version} must be at least ${MINIMUM_SECRET_LENGTH} characters long`,
			);
		}

		versions.add(secret.version);
	}

	return current;
};

/**
 * Creates the sealer. Every value gets its own AES-256-GCM key, derived with
 * HKDF from the current secret, a random salt and the purpose, so a value
 * sealed for one purpose never unseals for another and the number of sealed
 * values per secret has no nonce limit. Every rejection reports the same
 * `invalid-seal` error.
 */
export function createSealer(options: SealerOptions): Sealer {
	const { secrets } = options;
	const currentSecret = requireValidSecrets(secrets);
	const currentKey = importSecret(currentSecret.value);
	const secretKeys = new Map(
		secrets.map((secret) => [secret.version, importSecret(secret.value)]),
	);

	return {
		async seal(input) {
			if (
				!Number.isFinite(input.timeToLiveMilliseconds) ||
				input.timeToLiveMilliseconds <= 0
			) {
				throw new RangeError(
					"timeToLiveMilliseconds must be a positive finite number",
				);
			}

			const salt = randomBytes(SALT_BYTES);
			const initializationVector = randomBytes(INITIALIZATION_VECTOR_BYTES);
			const contents: SealedContents = {
				payload: own(input, "payload") ?? {},
				expiresAtMilliseconds: Date.now() + input.timeToLiveMilliseconds,
			};
			const ciphertext = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: initializationVector },
				await deriveMessageKey(await currentKey, salt, input.purpose),
				encoder.encode(JSON.stringify(contents)),
			);
			return `${currentSecret.version}.${toBase64Url(
				new Uint8Array([
					...salt,
					...initializationVector,
					...new Uint8Array(ciphertext),
				]),
			)}`;
		},
		async unseal(sealed, purpose) {
			const [, version, body] = SEALED_PATTERN.exec(sealed) ?? [];
			const secretKey =
				version === undefined ? undefined : secretKeys.get(Number(version));

			if (body === undefined || secretKey === undefined) {
				return fail("invalid-seal");
			}

			try {
				const bytes = fromBase64Url(body);
				const plaintext = await crypto.subtle.decrypt(
					{
						name: "AES-GCM",
						iv: bytes.slice(
							SALT_BYTES,
							SALT_BYTES + INITIALIZATION_VECTOR_BYTES,
						),
					},
					await deriveMessageKey(
						await secretKey,
						bytes.slice(0, SALT_BYTES),
						purpose,
					),
					bytes.slice(SALT_BYTES + INITIALIZATION_VECTOR_BYTES),
				);
				const contents: SealedContents = JSON.parse(decoder.decode(plaintext));

				if (!(Date.now() < contents.expiresAtMilliseconds)) {
					return fail("invalid-seal");
				}

				return succeed(contents.payload);
			} catch {
				return fail("invalid-seal");
			}
		},
	};
}
