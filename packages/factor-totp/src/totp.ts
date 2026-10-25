import {
	applyLimit,
	assertLimitRule,
	type Duration,
	ERROR_CODES,
	type FactorContext,
	type FactorPlugin,
	fail,
	type Limit,
	type LimitRule,
	type MeterRefusal,
	NO_LIMIT,
	type Proof,
	type Result,
	succeed,
} from "@vow-auth/core";
import { generateBackupCodes, hashBackupCode } from "./backup-codes.js";
import { decodeBase32, encodeBase32 } from "./base32.js";
import { DIGITS, findStep, PERIOD_SECONDS, SECRET_BYTES } from "./otp.js";
import type { TotpStore } from "./store.js";

const TOTP_PROVIDER = "totp";
const SECRET_PURPOSE = "totp-secret";
const NO_STEP_YET = -1;
const ALGORITHM_NAME = "SHA1";

/** What a limit is asked about: which subject is trying a code, and for what. */
export type TotpLimitInput = {
	readonly tenant: string;
	readonly subject: string;
	readonly action: "verify" | "confirm";
};

/** Options for creating the TOTP factor. */
export type TotpOptions = {
	readonly store: TotpStore;
	/** The name an app shows next to the code, such as the name of your service. */
	readonly issuer: string;
	/**
	 * How long a sealed secret stays readable, created with `defineDuration`.
	 * A person whose secret has expired has to enroll again, so choose the time
	 * you are ready to ask that after.
	 */
	readonly secretTimeToLive: Duration;
	/**
	 * How often codes may be tried for one subject. Six digits are guessable,
	 * so the answer is required: a rule and the scopes to count, or `"off"`
	 * when something in front limits it already. The engine counts it in its
	 * meter store.
	 */
	readonly limit: LimitRule<TotpLimitInput> | typeof NO_LIMIT;
	readonly now?: () => number;
};

/** What a person needs to add the secret to an app. */
export type TotpEnrollment = {
	/** The secret as base32 text, for typing into an app. */
	readonly secret: string;
	/** The otpauth address that a QR code carries; render it on your own page, never through a third party. */
	readonly uri: string;
};

/**
 * What the application may call on the TOTP factor. The factor itself signs
 * in the second step of a step-up: the response is `{ code }` or
 * `{ backupCode }`. It can only follow another factor: the person is the
 * subject that factor identified, never one the client names.
 */
export type Totp = {
	/** Starts an enrollment for a signed-in subject. Starting again before confirming replaces the secret; a confirmed enrollment must be removed first. */
	begin(input: {
		readonly tenant: string;
		readonly subject: string;
		readonly account: string;
	}): Promise<Result<TotpEnrollment>>;
	/** Confirms the enrollment with a first code and returns the backup codes, shown once. */
	confirm(input: {
		readonly tenant: string;
		readonly subject: string;
		readonly code: string;
	}): Promise<Result<readonly string[], string | MeterRefusal>>;
	/** Replaces the backup codes of a confirmed enrollment; the old ones stop working. */
	renewBackupCodes(input: {
		readonly tenant: string;
		readonly subject: string;
	}): Promise<Result<readonly string[]>>;
	/** Removes the enrollment. Ask for a fresh proof before you call it. */
	remove(input: {
		readonly tenant: string;
		readonly subject: string;
	}): Promise<boolean>;
};

const readText = (response: unknown, key: string): string | undefined => {
	if (typeof response !== "object" || response === null) {
		return undefined;
	}

	const value: unknown = Object.hasOwn(response, key)
		? Reflect.get(response, key)
		: undefined;

	return typeof value === "string" ? value : undefined;
};

const sameIdentity = (proof: Proof | undefined) => {
	if (proof === undefined) {
		return undefined;
	}

	const { provider, externalId, email, emailVerified } = proof.claims;

	return {
		provider,
		externalId,
		emailVerified,
		...(email === undefined ? {} : { email: email.address }),
	};
};

/**
 * Creates the TOTP factor: HMAC-SHA-1, six digits, steps of 30 seconds and
 * one step of drift either way, the one setting every authenticator app
 * understands. A code is accepted once: the step it came from becomes the
 * lowest the next code may come from, and the store has to make that atomic.
 * The secrets are sealed with the sealer of this factor alone, so the store
 * never holds one in the clear and no other part can open one.
 */
export function createTotp(options: TotpOptions): FactorPlugin<Totp> {
	assertLimitRule("limit", options.limit);

	const { store, issuer } = options;
	const now = options.now ?? Date.now;

	if (issuer === "" || issuer.includes(":")) {
		throw new RangeError("issuer must be a name without a colon");
	}

	return {
		strength: "possession",
		providers: [TOTP_PROVIDER],
		create({ sealer, createLimiter }) {
			const limit: Limit<TotpLimitInput> =
				options.limit === NO_LIMIT ? NO_LIMIT : createLimiter(options.limit);

			const openSecret = async (
				tenant: string,
				subject: string,
				sealed: string,
			): Promise<Uint8Array<ArrayBuffer> | undefined> => {
				const opened = await sealer.unseal(sealed, SECRET_PURPOSE);

				if (
					!opened.ok ||
					opened.value.tenant !== tenant ||
					opened.value.subject !== subject
				) {
					return undefined;
				}

				return decodeBase32(opened.value.secret ?? "");
			};

			const newBackupCodes = async () => {
				const codes = generateBackupCodes();

				return {
					codes,
					hashes: await Promise.all(codes.map((code) => hashBackupCode(code))),
				};
			};

			const verify = async (response: unknown, context: FactorContext) => {
				const { tenant, subject } = context;
				const claims = sameIdentity(context.proofs[0]);

				if (subject === undefined || claims === undefined) {
					return fail(ERROR_CODES.invalidProof);
				}

				const allowed = await applyLimit(limit, {
					tenant,
					subject,
					action: "verify",
				});

				if (!allowed.ok) {
					return fail(ERROR_CODES.rateLimited);
				}

				const record = await store.find(tenant, subject);

				if (record === undefined || !record.confirmed) {
					return fail(ERROR_CODES.invalidProof);
				}

				const backupCode = readText(response, "backupCode");

				if (backupCode !== undefined) {
					return (await store.spendBackupCode(
						tenant,
						subject,
						await hashBackupCode(backupCode),
					))
						? succeed(claims)
						: fail(ERROR_CODES.invalidProof);
				}

				const code = readText(response, "code");
				const secret = await openSecret(tenant, subject, record.sealedSecret);
				const step =
					code === undefined || secret === undefined
						? undefined
						: await findStep(secret, code, now());

				return step !== undefined &&
					(await store.advance(tenant, subject, step))
					? succeed(claims)
					: fail(ERROR_CODES.invalidProof);
			};

			return {
				verify,
				api: {
					async begin({ tenant, subject, account }) {
						if (account === "") {
							return fail(ERROR_CODES.invalidRequest);
						}

						const existing = await store.find(tenant, subject);

						if (existing?.confirmed) {
							return fail(ERROR_CODES.forbidden);
						}

						const secret = encodeBase32(
							crypto.getRandomValues(new Uint8Array(SECRET_BYTES)),
						);

						await store.save(tenant, subject, {
							sealedSecret: await sealer.seal({
								purpose: SECRET_PURPOSE,
								payload: { secret, tenant, subject },
								timeToLive: options.secretTimeToLive,
							}),
							confirmed: false,
							lastStep: NO_STEP_YET,
							backupCodeHashes: [],
						});

						const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
						const query = new URLSearchParams({
							secret,
							issuer,
							algorithm: ALGORITHM_NAME,
							digits: String(DIGITS),
							period: String(PERIOD_SECONDS),
						});

						return succeed({
							secret,
							uri: `otpauth://totp/${label}?${query.toString()}`,
						});
					},
					async confirm({ tenant, subject, code }) {
						const allowed = await applyLimit(limit, {
							tenant,
							subject,
							action: "confirm",
						});

						if (!allowed.ok) {
							return fail(allowed.error);
						}

						const record = await store.find(tenant, subject);

						if (record === undefined || record.confirmed) {
							return fail(ERROR_CODES.invalidRequest);
						}

						const secret = await openSecret(
							tenant,
							subject,
							record.sealedSecret,
						);
						const step =
							secret === undefined
								? undefined
								: await findStep(secret, code, now());

						if (
							step === undefined ||
							!(await store.advance(tenant, subject, step))
						) {
							return fail(ERROR_CODES.invalidProof);
						}

						const { codes, hashes } = await newBackupCodes();

						await store.save(tenant, subject, {
							...record,
							confirmed: true,
							lastStep: step,
							backupCodeHashes: hashes,
						});

						return succeed(codes);
					},
					async renewBackupCodes({ tenant, subject }) {
						const record = await store.find(tenant, subject);

						if (record === undefined || !record.confirmed) {
							return fail(ERROR_CODES.invalidRequest);
						}

						const { codes, hashes } = await newBackupCodes();

						await store.save(tenant, subject, {
							...record,
							backupCodeHashes: hashes,
						});

						return succeed(codes);
					},
					remove({ tenant, subject }) {
						return store.remove(tenant, subject);
					},
				},
			};
		},
	};
}
