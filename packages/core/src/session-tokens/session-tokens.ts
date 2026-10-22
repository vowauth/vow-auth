import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import type { Sealer } from "../sealer.js";
import { isBornSession, type Session } from "../session.js";
import { isPlainObject } from "../shared/is-plain-object.js";
import { own } from "../shared/own.js";
import { safeParseJson } from "../shared/safe-parse-json.js";
import type { ValueOf } from "../shared/value-of.js";
import type { EpochReading, EpochStore } from "./epoch-store.js";

/** Options for creating session tokens. */
export type SessionTokensOptions = {
	readonly sealer: Sealer;
	readonly epochs: EpochStore;
	/**
	 * The longest life time a session token may have. Revocation keys live
	 * exactly this long: token expiry and key lifetimes use the same clock of
	 * the epoch store, so a key outlives every token issued before its
	 * revocation without any margin.
	 */
	readonly maximumLifeTimeMilliseconds: number;
	readonly audit?: AuditSink | undefined;
};

/** Where a session token is used and how long it lives. */
export type IssueSessionTokenInput = {
	readonly tenant: string;
	readonly device: string;
	readonly timeToLiveMilliseconds: number;
};

/** The identity a valid session token carries. */
export type VerifiedSession = {
	readonly tenant: string;
	readonly subject: string;
	readonly device: string;
	readonly session: string;
};

/** A level to revoke; revoking a level revokes every token whose chain contains it. */
export type RevocationLevel =
	| {
			readonly tenant: string;
			readonly scope: typeof REVOCATION_SCOPES.tenant;
	  }
	| {
			readonly tenant: string;
			readonly scope:
				| typeof REVOCATION_SCOPES.user
				| typeof REVOCATION_SCOPES.device
				| typeof REVOCATION_SCOPES.session;
			readonly id: string;
	  };

/** Sealed session tokens with instant revocation of any level of their chain. */
export type SessionTokens = {
	issue(
		session: Session,
		input: IssueSessionTokenInput,
	): Promise<Result<string>>;
	verify(token: string): Promise<Result<VerifiedSession>>;
	revoke(level: RevocationLevel): Promise<void>;
};

export const REVOCATION_SCOPES = {
	tenant: "tenant",
	user: "user",
	device: "device",
	session: "session",
} as const;

type Scope = ValueOf<typeof REVOCATION_SCOPES>;
type ChainLink = {
	readonly scope: Scope;
	readonly id: string;
	readonly stamp: number;
};

const SESSION_PURPOSE = "session";
const CHAIN_SCOPES: readonly Scope[] = [
	REVOCATION_SCOPES.tenant,
	REVOCATION_SCOPES.user,
	REVOCATION_SCOPES.device,
	REVOCATION_SCOPES.session,
];

const keyOf = (tenant: string, scope: Scope, id: string): string => {
	return `{${encodeURIComponent(tenant)}}:${scope}:${encodeURIComponent(id)}`;
};

const readEpochs = async (
	epochs: EpochStore,
	keys: readonly string[],
): Promise<EpochReading> => {
	const reading = await epochs.read(keys);

	if (
		!Number.isFinite(reading.now) ||
		reading.stamps.length !== keys.length ||
		!reading.stamps.every(Number.isFinite)
	) {
		throw new Error(
			"EpochStore.read must return a finite time and one finite stamp per key",
		);
	}

	return reading;
};

const isLink = (
	value: unknown,
	scope: Scope | undefined,
): value is ChainLink => {
	return (
		isPlainObject(value) &&
		own(value, "scope") === scope &&
		typeof own(value, "id") === "string" &&
		Number.isFinite(own(value, "stamp"))
	);
};

const parseChain = (
	serialized: string | undefined,
): readonly ChainLink[] | undefined => {
	if (serialized === undefined) {
		return undefined;
	}

	const chain = safeParseJson(serialized);

	return Array.isArray(chain) &&
		chain.every((link, index) => isLink(link, CHAIN_SCOPES[index]))
		? chain
		: undefined;
};

/**
 * Creates session tokens. A token is a sealed chain `tenant → user → device →
 * session` with the revocation stamp of every level and the expiry, both read
 * from the epoch store at issue. It is valid only before its expiry by the
 * store's clock and while each stamp is at least the current one, so revoking
 * a level kills every token below it at once, and a verification costs one
 * read of the epoch store. The sealer's own expiry by the local clock is an
 * outer bound that can only reject earlier. Every rejection reports the same
 * `invalid-session` error; the audit records why, including which level was
 * revoked. Issuing is recorded before the token is made, so a failing sink
 * means no token; a revocation is made first and recorded after, so a failing
 * sink never blocks it. Successful verifications are not recorded: they are
 * the hot path.
 */
export function createSessionTokens(
	options: SessionTokensOptions,
): SessionTokens {
	const { sealer, epochs, maximumLifeTimeMilliseconds } = options;
	const audit = own(options, "audit");

	if (
		!Number.isFinite(maximumLifeTimeMilliseconds) ||
		maximumLifeTimeMilliseconds <= 0
	) {
		throw new RangeError(
			"maximumLifeTimeMilliseconds must be a positive finite number",
		);
	}

	return {
		async issue(session, input) {
			if (!isBornSession(session)) {
				return fail(ERROR_CODES.noSession);
			}

			if (
				!Number.isFinite(input.timeToLiveMilliseconds) ||
				input.timeToLiveMilliseconds <= 0 ||
				input.timeToLiveMilliseconds > maximumLifeTimeMilliseconds
			) {
				throw new RangeError(
					"timeToLiveMilliseconds must be positive and at most maximumLifeTimeMilliseconds",
				);
			}

			await report(audit, {
				event: AUDIT_EVENTS.sessionIssue,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.issued,
				tenant: input.tenant,
				subject: session.subject,
				detail: { device: input.device, session: session.id },
			});

			const levels: readonly { readonly scope: Scope; readonly id: string }[] =
				[
					{ scope: REVOCATION_SCOPES.tenant, id: input.tenant },
					{ scope: REVOCATION_SCOPES.user, id: session.subject },
					{ scope: REVOCATION_SCOPES.device, id: input.device },
					{ scope: REVOCATION_SCOPES.session, id: session.id },
				];

			const reading = await readEpochs(
				epochs,
				levels.map(({ scope, id }) => keyOf(input.tenant, scope, id)),
			);

			const chain = levels.map(
				({ scope, id }, index): ChainLink => ({
					scope,
					id,
					stamp: reading.stamps[index] ?? Number.NaN,
				}),
			);

			return succeed(
				await sealer.seal({
					purpose: SESSION_PURPOSE,
					payload: {
						chain: JSON.stringify(chain),
						expiresAtMilliseconds: String(
							reading.now + input.timeToLiveMilliseconds,
						),
					},
					timeToLiveMilliseconds: input.timeToLiveMilliseconds,
				}),
			);
		},
		async verify(token) {
			const refuse = async (
				reason: string,
				tenant: string,
				subject: string,
				detail: Readonly<Record<string, string>>,
			) => {
				await report(audit, {
					event: AUDIT_EVENTS.sessionVerify,
					outcome: AUDIT_OUTCOMES.refusal,
					reason,
					tenant,
					subject,
					detail,
				});

				return fail(ERROR_CODES.invalidSession);
			};

			const unsealed = await sealer.unseal(token, SESSION_PURPOSE);

			if (!unsealed.ok) {
				return refuse(AUDIT_REASONS.invalidSeal, "", "", {});
			}

			const chain = parseChain(own(unsealed.value, "chain"));
			const [tenantLink, user, device, session] = chain ?? [];

			if (
				chain === undefined ||
				tenantLink === undefined ||
				user === undefined ||
				device === undefined ||
				session === undefined
			) {
				return refuse(AUDIT_REASONS.malformedChain, "", "", {});
			}

			const tenant = tenantLink.id;

			const reading = await readEpochs(
				epochs,
				chain.map(({ scope, id }) => keyOf(tenant, scope, id)),
			);

			const expiresAtMilliseconds = Number(
				own(unsealed.value, "expiresAtMilliseconds"),
			);

			if (!(reading.now < expiresAtMilliseconds)) {
				return refuse(AUDIT_REASONS.expired, tenant, user.id, {
					device: device.id,
				});
			}

			const revokedIndex = chain.findIndex(
				(link, index) => !(link.stamp >= (reading.stamps[index] ?? Number.NaN)),
			);

			if (revokedIndex !== -1) {
				return refuse(AUDIT_REASONS.revoked, tenant, user.id, {
					device: device.id,
					scope: chain[revokedIndex]?.scope ?? "",
				});
			}

			return succeed({
				tenant,
				subject: user.id,
				device: device.id,
				session: session.id,
			});
		},
		async revoke(level) {
			const id =
				level.scope === REVOCATION_SCOPES.tenant ? level.tenant : level.id;

			await epochs.revoke(
				keyOf(level.tenant, level.scope, id),
				maximumLifeTimeMilliseconds,
			);

			await report(audit, {
				event: AUDIT_EVENTS.sessionRevoke,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.revoked,
				tenant: level.tenant,
				subject: level.scope === REVOCATION_SCOPES.user ? level.id : "",
				detail: { scope: level.scope, id },
			});
		},
	};
}
