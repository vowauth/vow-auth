import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "./audit.js";
import { type Duration, isDuration } from "./duration.js";
import { ERROR_CODES } from "./errors.js";
import { fail, type Result, succeed } from "./result.js";
import { isPlainObject } from "./shared/is-plain-object.js";
import { own } from "./shared/own.js";
import { safeParseJson } from "./shared/safe-parse-json.js";

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
	/**
	 * Whose values these are. The domain is part of every key, so a value of
	 * one domain never unseals in another whatever its purpose: a factor
	 * cannot seal a value that the core or another factor takes for its own.
	 * `core` when left out.
	 */
	readonly domain?: SealDomain | undefined;
	readonly audit?: AuditSink | undefined;
};

/** The owners of sealed values and one-time tokens: the core itself, or one factor. */
export type SealDomain = "core" | `factor:${string}`;

/** Parameters of a value to seal. */
export type SealInput = {
	readonly purpose: string;
	readonly payload?: Readonly<Record<string, string>>;
	readonly timeToLive: Duration;
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

type OpenResult =
	| { readonly payload: Readonly<Record<string, string>> }
	| { readonly reason: string };

const parseContents = (raw: unknown): SealedContents | undefined => {
	if (!isPlainObject(raw)) {
		return undefined;
	}

	const payload = own(raw, "payload");
	const expiresAtMilliseconds = own(raw, "expiresAtMilliseconds");

	if (
		!isPlainObject(payload) ||
		typeof expiresAtMilliseconds !== "number" ||
		!Number.isFinite(expiresAtMilliseconds)
	) {
		return undefined;
	}

	const entries: [string, string][] = [];

	for (const [key, value] of Object.entries(payload)) {
		if (typeof value !== "string") {
			return undefined;
		}

		entries.push([key, value]);
	}

	return { payload: Object.fromEntries(entries), expiresAtMilliseconds };
};

const MINIMUM_SECRET_LENGTH = 32;
const MINIMUM_SECRET_BITS = 128;
const MINIMUM_DISTINCT_CHARACTERS = 16;
const SALT_BYTES = 16;
const INITIALIZATION_VECTOR_BYTES = 12;
const MAXIMUM_VERSION_DIGITS = 9;

const KEY_DERIVATION_LABEL = "vow-auth/seal/v1/";

const DIGITS = new Set("0123456789");
const BASE64_URL_CHARACTERS = new Set(
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
);

const consistsOf = (text: string, alphabet: Set<string>): boolean => {
	return (
		text.length > 0 &&
		Array.from(text).every((character) => alphabet.has(character))
	);
};

const parseSealed = (
	sealed: string,
): { readonly version: number; readonly body: string } | undefined => {
	const separator = sealed.indexOf(".");
	const version = sealed.slice(0, separator);
	const body = sealed.slice(separator + 1);

	if (
		separator < 0 ||
		version.length > MAXIMUM_VERSION_DIGITS ||
		(version.length > 1 && version.startsWith("0")) ||
		!consistsOf(version, DIGITS) ||
		!consistsOf(body, BASE64_URL_CHARACTERS)
	) {
		return undefined;
	}

	return { version: Number(version), body };
};

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
	domain: SealDomain,
	purpose: string,
): Promise<CryptoKey> => {
	return crypto.subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt,
			info: encoder.encode(
				KEY_DERIVATION_LABEL + JSON.stringify([domain, purpose]),
			),
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

/**
 * Whether a secret looks generated rather than typed: enough distinct
 * characters, no repetition of a shorter part, and at least 128 bits by the
 * frequency of its own characters. It catches `aaaa…`, `abab…`, `0123…` and
 * placeholders; a secret from `openssl rand -base64 32` always passes.
 */
const looksRandom = (value: string): boolean => {
	const characters = [...value];
	const counts = new Map<string, number>();

	for (const character of characters) {
		counts.set(character, (counts.get(character) ?? 0) + 1);
	}

	let bitsPerCharacter = 0;

	for (const count of counts.values()) {
		const share = count / characters.length;

		bitsPerCharacter -= share * Math.log2(share);
	}

	const periodic = Array.from(
		{ length: Math.floor(characters.length / 2) },
		(_, index) => index + 1,
	).some(
		(period) =>
			characters.length % period === 0 &&
			characters.every(
				(character, index) => character === characters[index % period],
			),
	);

	return (
		counts.size >= MINIMUM_DISTINCT_CHARACTERS &&
		!periodic &&
		bitsPerCharacter * characters.length >= MINIMUM_SECRET_BITS
	);
};

const requireValidSecrets = (
	secrets: readonly SecretVersion[],
): SecretVersion => {
	const [current] = secrets;

	if (current === undefined) {
		throw new RangeError("secrets must contain at least one secret");
	}

	const versions = new Set<number>();
	const values = new Set<string>();

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

		if (!looksRandom(secret.value)) {
			throw new RangeError(
				`Secret version ${secret.version} does not look random; generate one with \`openssl rand -base64 32\``,
			);
		}

		if (values.has(secret.value)) {
			throw new RangeError(
				`Secret version ${secret.version} repeats the value of another version`,
			);
		}

		versions.add(secret.version);
		values.add(secret.value);
	}

	return current;
};

/**
 * Creates the sealer. Every value gets its own AES-256-GCM key, derived with
 * HKDF from the current secret, a random salt, the domain and the purpose, so
 * a value sealed for one purpose or domain never unseals for another and the
 * number of sealed
 * values per secret has no nonce limit. Every rejection reports the same
 * `invalid-seal` error; the audit records why: malformed, unknown secret
 * version, undecryptable (wrong purpose, wrong secret or tampered) or expired.
 */
export function createSealer(options: SealerOptions): Sealer {
	const { secrets } = options;

	const audit = own(options, "audit");
	const domain = own(options, "domain") ?? "core";

	const currentSecret = requireValidSecrets(secrets);
	const currentKey = importSecret(currentSecret.value);

	const secretKeys = new Map(
		secrets.map((secret) => [secret.version, importSecret(secret.value)]),
	);

	const open = async (sealed: string, purpose: string): Promise<OpenResult> => {
		const parsed = parseSealed(sealed);

		if (parsed === undefined) {
			return { reason: AUDIT_REASONS.malformed };
		}

		const secretKey = secretKeys.get(parsed.version);

		if (secretKey === undefined) {
			return { reason: AUDIT_REASONS.unknownVersion };
		}

		try {
			const bytes = fromBase64Url(parsed.body);

			const plaintext = await crypto.subtle.decrypt(
				{
					name: "AES-GCM",
					iv: bytes.slice(SALT_BYTES, SALT_BYTES + INITIALIZATION_VECTOR_BYTES),
				},
				await deriveMessageKey(
					await secretKey,
					bytes.slice(0, SALT_BYTES),
					domain,
					purpose,
				),
				bytes.slice(SALT_BYTES + INITIALIZATION_VECTOR_BYTES),
			);

			const contents = parseContents(safeParseJson(decoder.decode(plaintext)));

			if (contents === undefined) {
				return { reason: AUDIT_REASONS.undecryptable };
			}

			return Date.now() < contents.expiresAtMilliseconds
				? { payload: contents.payload }
				: { reason: AUDIT_REASONS.expired };
		} catch {
			return { reason: AUDIT_REASONS.undecryptable };
		}
	};

	return {
		async seal(input) {
			if (!isDuration(input.timeToLive)) {
				throw new TypeError("timeToLive must come from defineDuration");
			}

			const salt = randomBytes(SALT_BYTES);
			const initializationVector = randomBytes(INITIALIZATION_VECTOR_BYTES);

			const contents: SealedContents = {
				payload: own(input, "payload") ?? {},
				expiresAtMilliseconds: Date.now() + input.timeToLive.milliseconds,
			};

			const ciphertext = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: initializationVector },
				await deriveMessageKey(await currentKey, salt, domain, input.purpose),
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
			const opened = await open(sealed, purpose);

			if ("reason" in opened) {
				await report(audit, {
					event: AUDIT_EVENTS.sealUnseal,
					outcome: AUDIT_OUTCOMES.refusal,
					reason: opened.reason,
					tenant: "",
					subject: "",
					detail: { purpose },
				});

				return fail(ERROR_CODES.invalidSeal);
			}

			return succeed(opened.payload);
		},
	};
}
