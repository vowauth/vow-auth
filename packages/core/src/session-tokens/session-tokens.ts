import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { type Duration, isDuration } from "../duration.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import type { Sealer } from "../sealer.js";
import { isBornSession, type Session } from "../session.js";
import { isPlainObject } from "../shared/is-plain-object.js";
import { isStorableText } from "../shared/is-storable-text.js";
import { own } from "../shared/own.js";
import { safeParseJson } from "../shared/safe-parse-json.js";
import { generateSecret } from "../shared/secret.js";
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
	readonly timeToLive: Duration;
	/** The ids of the factors the person passed to get this session, in order. */
	readonly methods: readonly string[];
};

/** The identity a valid session token carries. */
export type VerifiedSession = {
	readonly tenant: string;
	readonly subject: string;
	readonly device: string;
	readonly session: string;
	/** The ids of the factors passed to get this session, in order. */
	readonly methods: readonly string[];
	/** When the person last proved who they are, by the epoch store's clock. */
	readonly authenticatedAtMilliseconds: number;
	/**
	 * How long ago that was, by the same clock at the moment of this check. An
	 * application that wants a recent sign in for a sensitive action compares
	 * this to its limit and asks the person to sign in again when it is over.
	 */
	readonly authenticationAgeMilliseconds: number;
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
				| typeof REVOCATION_SCOPES.session
				| typeof REVOCATION_SCOPES.agent
				| typeof REVOCATION_SCOPES.delegation;
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
	/**
	 * Lets an agent act for the person whose session token is given. The token
	 * is checked here, so the delegator, the tenant and the device cannot be
	 * made up by the caller.
	 */
	delegate(
		sessionToken: string,
		input: DelegateInput,
	): Promise<Result<Delegation>>;
	/** Checks an agent token; a session token is not accepted here, nor an agent token by verify. */
	verifyAgent(token: string): Promise<Result<VerifiedAgent>>;
};

/** What a person lets an agent do, and for how long. */
export type DelegateInput = {
	/** Names the agent. Revoking the agent revokes every delegation to it, of every person. */
	readonly agent: string;
	readonly timeToLive: Duration;
	/**
	 * Ties the delegation to the device and session it was made from, so that
	 * signing out of them stops the agent. Without it the agent outlives the
	 * session, as an OAuth grant does, until the delegation, the agent or the
	 * person is revoked.
	 */
	readonly boundToSession?: boolean;
};

/** A delegation that was made: the agent's bearer token and the id to revoke it by. */
export type Delegation = {
	readonly token: string;
	readonly delegation: string;
};

/** The agent a valid agent token carries, and the person it acts for. */
export type VerifiedAgent = {
	readonly tenant: string;
	/** The person the agent acts for. */
	readonly subject: string;
	readonly agent: string;
	readonly delegation: string;
	/** The device and session the delegation is tied to, or undefined when it is not. */
	readonly boundTo:
		| { readonly device: string; readonly session: string }
		| undefined;
	readonly delegatedAtMilliseconds: number;
};

export const REVOCATION_SCOPES = {
	tenant: "tenant",
	user: "user",
	device: "device",
	session: "session",
	agent: "agent",
	delegation: "delegation",
} as const;

type Scope = ValueOf<typeof REVOCATION_SCOPES>;
type ChainLink = {
	readonly scope: Scope;
	readonly id: string;
	readonly stamp: number;
};

const SESSION_PURPOSE = "session";
const AGENT_PURPOSE = "agent";
const SESSION_SHAPE: readonly Scope[] = [
	REVOCATION_SCOPES.tenant,
	REVOCATION_SCOPES.user,
	REVOCATION_SCOPES.device,
	REVOCATION_SCOPES.session,
];
const AGENT_SHAPES: readonly (readonly Scope[])[] = [
	[
		REVOCATION_SCOPES.tenant,
		REVOCATION_SCOPES.user,
		REVOCATION_SCOPES.agent,
		REVOCATION_SCOPES.delegation,
	],
	[...SESSION_SHAPE, REVOCATION_SCOPES.agent, REVOCATION_SCOPES.delegation],
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

const parseMethods = (
	raw: string | undefined,
): readonly string[] | undefined => {
	const parsed = raw === undefined ? undefined : safeParseJson(raw);

	return Array.isArray(parsed) &&
		parsed.length > 0 &&
		parsed.every((method) => typeof method === "string" && method !== "")
		? parsed
		: undefined;
};

const parseChain = (
	serialized: string | undefined,
	shapes: readonly (readonly Scope[])[],
): readonly ChainLink[] | undefined => {
	if (serialized === undefined) {
		return undefined;
	}

	const chain = safeParseJson(serialized);

	return Array.isArray(chain) &&
		shapes.some(
			(shape) =>
				shape.length === chain.length &&
				chain.every((link, index) => isLink(link, shape[index])),
		)
		? chain
		: undefined;
};

type Inspection<Extra> = {
	readonly tenant: string;
	readonly subject: string;
	readonly chain: readonly ChainLink[];
	readonly now: number;
	readonly extra: Extra;
};

const idOf = (
	chain: readonly ChainLink[],
	scope: Scope,
): string | undefined => {
	return chain.find((link) => link.scope === scope)?.id;
};

const detailOf = (chain: readonly ChainLink[]): Record<string, string> => {
	const detail: Record<string, string> = {};

	for (const scope of [
		REVOCATION_SCOPES.device,
		REVOCATION_SCOPES.agent,
		REVOCATION_SCOPES.delegation,
	]) {
		const id = idOf(chain, scope);

		if (id !== undefined) {
			detail[scope] = id;
		}
	}

	return detail;
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

	const inspect = async <Extra>(
		token: string,
		purpose: string,
		shapes: readonly (readonly Scope[])[],
		parseExtra: (
			payload: Readonly<Record<string, string>>,
		) => Extra | undefined,
	): Promise<Result<Inspection<Extra>>> => {
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

		const unsealed = await sealer.unseal(token, purpose);

		if (!unsealed.ok) {
			return refuse(AUDIT_REASONS.invalidSeal, "", "", {});
		}

		const chain = parseChain(own(unsealed.value, "chain"), shapes);
		const [tenantLink, user] = chain ?? [];

		if (chain === undefined || tenantLink === undefined || user === undefined) {
			return refuse(AUDIT_REASONS.malformedChain, "", "", {});
		}

		const tenant = tenantLink.id;
		const detail = detailOf(chain);
		const reading = await readEpochs(
			epochs,
			chain.map(({ scope, id }) => keyOf(tenant, scope, id)),
		);
		const expiresAtMilliseconds = Number(
			own(unsealed.value, "expiresAtMilliseconds"),
		);

		if (!(reading.now < expiresAtMilliseconds)) {
			return refuse(AUDIT_REASONS.expired, tenant, user.id, detail);
		}

		const extra = parseExtra(unsealed.value);

		if (extra === undefined) {
			return refuse(AUDIT_REASONS.malformed, tenant, user.id, detail);
		}

		const revokedIndex = chain.findIndex(
			(link, index) => !(link.stamp >= (reading.stamps[index] ?? Number.NaN)),
		);

		if (revokedIndex !== -1) {
			return refuse(AUDIT_REASONS.revoked, tenant, user.id, {
				...detail,
				scope: chain[revokedIndex]?.scope ?? "",
			});
		}

		return succeed({
			tenant,
			subject: user.id,
			chain,
			now: reading.now,
			extra,
		});
	};

	const verifySession = async (
		token: string,
	): Promise<Result<VerifiedSession>> => {
		const inspected = await inspect(
			token,
			SESSION_PURPOSE,
			[SESSION_SHAPE],
			(payload) => {
				const authenticatedAt = Number(
					own(payload, "authenticatedAtMilliseconds"),
				);
				const methods = parseMethods(own(payload, "methods"));

				return methods === undefined || !Number.isFinite(authenticatedAt)
					? undefined
					: { methods, authenticatedAt };
			},
		);

		if (!inspected.ok) {
			return fail(inspected.error);
		}

		const { tenant, subject, chain, now, extra } = inspected.value;
		const device = idOf(chain, REVOCATION_SCOPES.device);
		const session = idOf(chain, REVOCATION_SCOPES.session);

		if (device === undefined || session === undefined) {
			return fail(ERROR_CODES.invalidSession);
		}

		return succeed({
			tenant,
			subject,
			device,
			session,
			methods: extra.methods,
			authenticatedAtMilliseconds: extra.authenticatedAt,
			authenticationAgeMilliseconds: Math.max(0, now - extra.authenticatedAt),
		});
	};

	return {
		async issue(session, input) {
			if (!isBornSession(session)) {
				return fail(ERROR_CODES.noSession);
			}

			if (
				!isDuration(input.timeToLive) ||
				input.timeToLive.milliseconds > maximumLifeTimeMilliseconds
			) {
				return fail(ERROR_CODES.invalidRequest);
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
							reading.now + input.timeToLive.milliseconds,
						),
						authenticatedAtMilliseconds: String(reading.now),
						methods: JSON.stringify(input.methods),
					},
					timeToLive: input.timeToLive,
				}),
			);
		},
		verify: verifySession,
		async verifyAgent(token) {
			const inspected = await inspect(
				token,
				AGENT_PURPOSE,
				AGENT_SHAPES,
				(payload) => {
					const delegatedAt = Number(own(payload, "delegatedAtMilliseconds"));

					return Number.isFinite(delegatedAt) ? delegatedAt : undefined;
				},
			);

			if (!inspected.ok) {
				return fail(inspected.error);
			}

			const { tenant, subject, chain, extra } = inspected.value;
			const agent = idOf(chain, REVOCATION_SCOPES.agent);
			const delegation = idOf(chain, REVOCATION_SCOPES.delegation);
			const device = idOf(chain, REVOCATION_SCOPES.device);
			const session = idOf(chain, REVOCATION_SCOPES.session);

			if (agent === undefined || delegation === undefined) {
				return fail(ERROR_CODES.invalidSession);
			}

			return succeed({
				tenant,
				subject,
				agent,
				delegation,
				boundTo:
					device === undefined || session === undefined
						? undefined
						: { device, session },
				delegatedAtMilliseconds: extra,
			});
		},
		async delegate(sessionToken, input) {
			const delegator = await verifySession(sessionToken);

			if (!delegator.ok) {
				return fail(ERROR_CODES.invalidSession);
			}

			const agent = own(input, "agent");
			const timeToLive = own(input, "timeToLive");

			if (
				!isStorableText(agent) ||
				!isDuration(timeToLive) ||
				timeToLive.milliseconds > maximumLifeTimeMilliseconds
			) {
				return fail(ERROR_CODES.invalidRequest);
			}

			const { tenant, subject, device, session } = delegator.value;
			const bound = own(input, "boundToSession") === true;
			const delegation = generateSecret();
			const levels: readonly { readonly scope: Scope; readonly id: string }[] =
				[
					{ scope: REVOCATION_SCOPES.tenant, id: tenant },
					{ scope: REVOCATION_SCOPES.user, id: subject },
					...(bound
						? [
								{ scope: REVOCATION_SCOPES.device, id: device },
								{ scope: REVOCATION_SCOPES.session, id: session },
							]
						: []),
					{ scope: REVOCATION_SCOPES.agent, id: agent },
					{ scope: REVOCATION_SCOPES.delegation, id: delegation },
				];

			await report(audit, {
				event: AUDIT_EVENTS.delegationGrant,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.issued,
				tenant,
				subject,
				detail: { agent, delegation, bound: String(bound) },
			});

			const reading = await readEpochs(
				epochs,
				levels.map(({ scope, id }) => keyOf(tenant, scope, id)),
			);
			const chain = levels.map(
				({ scope, id }, index): ChainLink => ({
					scope,
					id,
					stamp: reading.stamps[index] ?? Number.NaN,
				}),
			);

			return succeed({
				token: await sealer.seal({
					purpose: AGENT_PURPOSE,
					payload: {
						chain: JSON.stringify(chain),
						expiresAtMilliseconds: String(
							reading.now + timeToLive.milliseconds,
						),
						delegatedAtMilliseconds: String(reading.now),
					},
					timeToLive,
				}),
				delegation,
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
