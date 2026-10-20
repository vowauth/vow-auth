import { fail, type Result, succeed } from "../result.js";
import type { Sealer } from "../sealer.js";
import { isBornSession, type Session } from "../session.js";
import { own } from "../shared/own.js";
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
	| { readonly tenant: string; readonly scope: "tenant" }
	| {
			readonly tenant: string;
			readonly scope: "user" | "device" | "session";
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

type Scope = "tenant" | "user" | "device" | "session";
type Link = readonly [scope: Scope, id: string, stamp: number];

const SESSION_PURPOSE = "session";
const CHAIN_SCOPES: readonly Scope[] = ["tenant", "user", "device", "session"];

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

const isLink = (value: unknown, scope: Scope | undefined): value is Link => {
	return (
		Array.isArray(value) &&
		value.length === 3 &&
		value[0] === scope &&
		typeof value[1] === "string" &&
		Number.isFinite(value[2])
	);
};

const parseChain = (
	serialized: string | undefined,
): readonly Link[] | undefined => {
	if (serialized === undefined) {
		return undefined;
	}

	try {
		const chain: unknown = JSON.parse(serialized);

		return Array.isArray(chain) &&
			chain.every((link, index) => isLink(link, CHAIN_SCOPES[index]))
			? chain
			: undefined;
	} catch {
		return undefined;
	}
};

const tenantOf = (chain: readonly Link[]): string => {
	const [tenantLink] = chain;

	return tenantLink === undefined ? "" : tenantLink[1];
};

/**
 * Creates session tokens. A token is a sealed chain `tenant → user → device →
 * session` with the revocation stamp of every level and the expiry, both read
 * from the epoch store at issue. It is valid only before its expiry by the
 * store's clock and while each stamp is at least the current one, so revoking
 * a level kills every token below it at once, and a verification costs one
 * read of the epoch store. The sealer's own expiry by the local clock is an
 * outer bound that can only reject earlier. Every rejection reports the same
 * `invalid-session` error.
 */
export function createSessionTokens(
	options: SessionTokensOptions,
): SessionTokens {
	const { sealer, epochs, maximumLifeTimeMilliseconds } = options;

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
				return fail("no-session");
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

			const levels: readonly (readonly [Scope, string])[] = [
				["tenant", input.tenant],
				["user", session.subject],
				["device", input.device],
				["session", session.id],
			];
			const reading = await readEpochs(
				epochs,
				levels.map(([scope, id]) => keyOf(input.tenant, scope, id)),
			);
			const chain = levels.map(
				([scope, id], index): Link => [
					scope,
					id,
					reading.stamps[index] ?? Number.NaN,
				],
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
			const unsealed = await sealer.unseal(token, SESSION_PURPOSE);
			const chain = unsealed.ok
				? parseChain(own(unsealed.value, "chain"))
				: undefined;

			if (chain === undefined) {
				return fail("invalid-session");
			}

			const tenant = tenantOf(chain);
			const reading = await readEpochs(
				epochs,
				chain.map(([scope, id]) => keyOf(tenant, scope, id)),
			);
			const expiresAtMilliseconds = Number(
				unsealed.ok ? own(unsealed.value, "expiresAtMilliseconds") : undefined,
			);
			const [, user, device, session] = chain;

			if (
				user === undefined ||
				device === undefined ||
				session === undefined ||
				!(reading.now < expiresAtMilliseconds) ||
				!chain.every(
					([, , stamp], index) =>
						stamp >= (reading.stamps[index] ?? Number.NaN),
				)
			) {
				return fail("invalid-session");
			}

			return succeed({
				tenant,
				subject: user[1],
				device: device[1],
				session: session[1],
			});
		},
		async revoke(level) {
			const id = level.scope === "tenant" ? level.tenant : level.id;

			await epochs.revoke(
				keyOf(level.tenant, level.scope, id),
				maximumLifeTimeMilliseconds,
			);
		},
	};
}
