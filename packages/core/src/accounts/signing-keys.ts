import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import type { SecretBox } from "../secret-box.js";
import { toBase64Url } from "../shared/base64-url.js";
import { isPlainObject } from "../shared/is-plain-object.js";
import { isStorableText } from "../shared/is-storable-text.js";
import { own } from "../shared/own.js";
import { safeParseJson } from "../shared/safe-parse-json.js";
import type {
	AccountStore,
	NewSigningKey,
	SigningKeyReading,
	SigningKeyState,
	StoredSigningKey,
	TenantSigningKey,
} from "./account-store.js";
import type { Records } from "./records.js";

/** The private JWK of a signing key: ES256 on P-256, its kid the RFC 7638 thumbprint. */
export type PrivateSigningJwk = {
	readonly kty: "EC";
	readonly crv: "P-256";
	readonly x: string;
	readonly y: string;
	readonly d: string;
	readonly kid: string;
	readonly alg: "ES256";
	readonly use: "sig";
};

/** A signing key opened for use. */
export type OpenedSigningKey = TenantSigningKey & {
	readonly privateJwk: PrivateSigningJwk;
};

/** The signing keys of a tenant, opened, by kid, with the version of the tenant they were read with. */
export type TenantSigningKeys = {
	readonly version: number;
	readonly keys: readonly OpenedSigningKey[];
};

/** Rotation and revocation of the signing keys of tenants. */
export type SigningKeyRotation = {
	/**
	 * Lets the next key sign, keeps the current one only to check what it
	 * signed, drops the previous one and publishes a new next key. The first
	 * rotation of a tenant creates its current and next keys. Refuses with
	 * `too-soon` until the next key has been published for the propagation time.
	 */
	rotateSigningKey(
		tenant: string,
	): Promise<Result<readonly TenantSigningKey[]>>;
	/**
	 * Removes a key at once, whatever its state, for a key that leaked. When it
	 * was the current key, the next one signs from now on, with no waiting; a
	 * new next key is published in place of a revoked or promoted one.
	 */
	revokeSigningKey(
		tenant: string,
		kid: string,
	): Promise<Result<readonly TenantSigningKey[]>>;
};

/** What the signing keys need. */
export type SigningKeysOptions = {
	readonly store: AccountStore;
	readonly records: Records;
	readonly box: SecretBox;
	/** How long a next key is published before a rotation lets it sign. */
	readonly propagationMilliseconds: number;
	readonly audit?: AuditSink | undefined;
};

const encoder = new TextEncoder();

const contextOf = (tenant: string, kid: string): readonly string[] => [
	"signing-key",
	tenant,
	kid,
];

const listedAs = (
	keys: readonly TenantSigningKey[],
	listed: readonly TenantSigningKey[],
): boolean =>
	keys.length === listed.length &&
	keys.every((key) =>
		listed.some((entry) => entry.kid === key.kid && entry.state === key.state),
	);

const thumbprintOf = async (x: string, y: string): Promise<string> =>
	toBase64Url(
		new Uint8Array(
			await crypto.subtle.digest(
				"SHA-256",
				encoder.encode(JSON.stringify({ crv: "P-256", kty: "EC", x, y })),
			),
		),
	);

const readJwk = (text: string, kid: string): PrivateSigningJwk | undefined => {
	const parsed = safeParseJson(text);

	if (!isPlainObject(parsed)) {
		return undefined;
	}

	const x = own(parsed, "x");
	const y = own(parsed, "y");
	const d = own(parsed, "d");

	if (
		own(parsed, "kty") !== "EC" ||
		own(parsed, "crv") !== "P-256" ||
		own(parsed, "kid") !== kid ||
		own(parsed, "alg") !== "ES256" ||
		own(parsed, "use") !== "sig" ||
		typeof x !== "string" ||
		typeof y !== "string" ||
		typeof d !== "string"
	) {
		return undefined;
	}

	return Object.freeze({
		kty: "EC",
		crv: "P-256",
		x,
		y,
		d,
		kid,
		alg: "ES256",
		use: "sig",
	});
};

/**
 * Creates the signing keys of tenants. Each tenant has no keys until its
 * first rotation, and from then on one current key that signs and one next
 * key published ahead of it, plus the previous key while it may still be
 * needed to check tokens. The private key is boxed for its tenant and kid, so
 * a row moved to another tenant does not open. Every change raises the
 * version of the tenant and is written with it at once; a rotation records
 * itself before it is made, as it puts a new key to work, and a revocation
 * after, as it takes one away. A key pair is generated extractable on
 * purpose, the one exception to keeping keys inside Web Crypto: its private
 * key leaves once, to be boxed for the store and handed to the authorization
 * server as a JWK.
 */
export function createSigningKeys(
	options: SigningKeysOptions,
): SigningKeyRotation & {
	/** The keys of an enabled tenant, opened; a tenant or a key changed past the engine refuses with `invalid-record`. */
	load(tenant: string): Promise<Result<TenantSigningKeys>>;
} {
	const { store, records, box, propagationMilliseconds, audit } = options;

	const refuse = async (
		event: string,
		reason: string,
		code: string,
		tenant: string,
		detail: Readonly<Record<string, string>> = {},
	) => {
		await report(audit, {
			event,
			outcome: AUDIT_OUTCOMES.refusal,
			reason,
			tenant,
			subject: "",
			detail,
		});

		return fail(code);
	};

	const read = async (
		event: string,
		tenant: string,
	): Promise<Result<SigningKeyReading>> => {
		if (!isStorableText(tenant)) {
			return refuse(
				event,
				AUDIT_REASONS.malformed,
				ERROR_CODES.invalidRequest,
				"",
			);
		}

		const reading = await store.getSigningKeys(tenant);

		if (reading === undefined) {
			return refuse(
				event,
				AUDIT_REASONS.notFound,
				ERROR_CODES.noTenant,
				tenant,
			);
		}

		if (
			!listedAs(reading.keys, reading.tenant.signingKeys) ||
			(await records.checkTenant(reading.tenant)) === "invalid"
		) {
			return refuse(
				event,
				AUDIT_REASONS.invalidRecord,
				ERROR_CODES.invalidRecord,
				tenant,
			);
		}

		return succeed(reading);
	};

	const generate = async (
		tenant: string,
		state: SigningKeyState,
	): Promise<NewSigningKey> => {
		// nosemgrep: extractable-key
		const pair = await crypto.subtle.generateKey(
			{ name: "ECDSA", namedCurve: "P-256" },
			true,
			["sign", "verify"],
		);
		const { x, y, d } = await crypto.subtle.exportKey("jwk", pair.privateKey);

		if (
			typeof x !== "string" ||
			typeof y !== "string" ||
			typeof d !== "string"
		) {
			throw new Error("An exported P-256 key must have x, y and d");
		}

		const kid = await thumbprintOf(x, y);
		const jwk: PrivateSigningJwk = {
			kty: "EC",
			crv: "P-256",
			x,
			y,
			d,
			kid,
			alg: "ES256",
			use: "sig",
		};

		return {
			kid,
			state,
			privateKey: await box.seal(JSON.stringify(jwk), contextOf(tenant, kid)),
		};
	};

	const kept = (
		key: StoredSigningKey,
		state: SigningKeyState,
	): NewSigningKey => ({ kid: key.kid, state, privateKey: key.privateKey });

	const write = async (
		reading: SigningKeyReading,
		keys: readonly NewSigningKey[],
	): Promise<readonly TenantSigningKey[] | undefined> => {
		const next = await records.tenant({
			...reading.tenant,
			version: reading.tenant.version + 1,
			signingKeys: keys.map((key) => ({ kid: key.kid, state: key.state })),
		});

		return (await store.setSigningKeys(next, reading.tenant.seal, keys))
			? next.signingKeys
			: undefined;
	};

	return {
		async rotateSigningKey(tenant) {
			const event = AUDIT_EVENTS.signingKeyChange;
			const reading = await read(event, tenant);

			if (!reading.ok) {
				return reading;
			}

			const { keys, now } = reading.value;
			const current = keys.find((key) => key.state === "current");
			const next = keys.find((key) => key.state === "next");
			let written: NewSigningKey[];

			if (keys.length === 0) {
				written = [
					await generate(tenant, "current"),
					await generate(tenant, "next"),
				];
			} else if (current === undefined || next === undefined) {
				return refuse(
					event,
					AUDIT_REASONS.invalidRecord,
					ERROR_CODES.invalidRecord,
					tenant,
				);
			} else if (now < next.publishedAtMilliseconds + propagationMilliseconds) {
				return refuse(
					event,
					AUDIT_REASONS.tooSoon,
					ERROR_CODES.tooSoon,
					tenant,
					{ kid: next.kid },
				);
			} else {
				written = [
					kept(next, "current"),
					kept(current, "previous"),
					await generate(tenant, "next"),
				];
			}

			const promoted = written.find((key) => key.state === "current");

			await report(audit, {
				event,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.rotated,
				tenant,
				subject: "",
				detail: { kid: promoted?.kid ?? "" },
			});

			const result = await write(reading.value, written);

			return result === undefined
				? refuse(event, AUDIT_REASONS.conflict, ERROR_CODES.conflict, tenant)
				: succeed(result);
		},
		async revokeSigningKey(tenant, kid) {
			const event = AUDIT_EVENTS.signingKeyChange;

			if (!isStorableText(kid)) {
				return refuse(
					event,
					AUDIT_REASONS.malformed,
					ERROR_CODES.invalidRequest,
					"",
				);
			}

			const reading = await read(event, tenant);

			if (!reading.ok) {
				return reading;
			}

			const { keys } = reading.value;
			const revoked = keys.find((key) => key.kid === kid);

			if (revoked === undefined) {
				return refuse(
					event,
					AUDIT_REASONS.notFound,
					ERROR_CODES.noKey,
					tenant,
					{ kid },
				);
			}

			const rest = keys.filter((key) => key.kid !== kid);
			const next = rest.find((key) => key.state === "next");
			let written: NewSigningKey[] = rest.map((key) => kept(key, key.state));

			if (revoked.state === "current") {
				written = [
					...rest
						.filter((key) => key.state === "previous")
						.map((key) => kept(key, "previous")),
					next === undefined
						? await generate(tenant, "current")
						: kept(next, "current"),
					await generate(tenant, "next"),
				];
			} else if (revoked.state === "next") {
				written = [...written, await generate(tenant, "next")];
			}

			const result = await write(reading.value, written);

			if (result === undefined) {
				return refuse(
					event,
					AUDIT_REASONS.conflict,
					ERROR_CODES.conflict,
					tenant,
					{
						kid,
					},
				);
			}

			await report(audit, {
				event,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.revoked,
				tenant,
				subject: "",
				detail: { kid },
			});

			return succeed(result);
		},
		async load(tenant) {
			const event = AUDIT_EVENTS.signingKeyLoad;
			const reading = await read(event, tenant);

			if (!reading.ok) {
				return reading;
			}

			if (reading.value.tenant.disabled) {
				return refuse(
					event,
					AUDIT_REASONS.disabled,
					ERROR_CODES.noTenant,
					tenant,
				);
			}

			const opened: OpenedSigningKey[] = [];

			for (const key of reading.value.keys) {
				const text = await box.open(key.privateKey, contextOf(tenant, key.kid));
				const privateJwk =
					text === undefined ? undefined : readJwk(text, key.kid);

				if (privateJwk === undefined) {
					return refuse(
						event,
						AUDIT_REASONS.undecryptable,
						ERROR_CODES.invalidRecord,
						tenant,
						{ kid: key.kid },
					);
				}

				opened.push(
					Object.freeze({ kid: key.kid, state: key.state, privateJwk }),
				);
			}

			return succeed(
				Object.freeze({
					version: reading.value.tenant.version,
					keys: Object.freeze(opened),
				}),
			);
		},
	};
}
