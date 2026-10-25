import type { Records } from "../accounts/records.js";
import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { type Duration, isDuration } from "../duration.js";
import { ERROR_CODES } from "../errors.js";
import { type Proof, restoreProof, serializeProof } from "../proof.js";
import { fail, type Result, succeed } from "../result.js";
import { isBornSession, type Session } from "../session.js";
import { isStorableText } from "../shared/is-storable-text.js";
import { own } from "../shared/own.js";
import { safeParseJson } from "../shared/safe-parse-json.js";
import { generateSecret, hashSecret } from "../shared/secret.js";
import type {
	GrantStore,
	RevocationLevel,
	StoredGrant,
} from "./grant-store.js";

const SESSION_PREFIX = "vas_";
const AGENT_PREFIX = "vag_";
const TOKEN_BODY = /^[0-9a-f]{64}$/;

/** Where a new session is used and what proved it. */
export type IssueSessionInput = {
	readonly accountId: string;
	readonly tenant: string;
	readonly subjectId: string;
	readonly device: string;
	/** The proofs of the sign in, in order. */
	readonly proofs: readonly Proof[];
};

/** Who a valid session token is in the tenant it was checked for. */
export type VerifiedSession = {
	readonly account: string;
	readonly tenant: string;
	readonly subject: string;
	readonly device: string;
	readonly session: string;
	/** The ids of the factors passed to get this session, in order. */
	readonly methods: readonly string[];
	/** When the person last proved who they are, by the store's clock. */
	readonly authenticatedAtMilliseconds: number;
	/**
	 * How long ago that was, by the same clock at the moment of this check. An
	 * application that wants a recent sign in for a sensitive action compares
	 * this to its limit and asks the person to sign in again when it is over.
	 */
	readonly authenticationAgeMilliseconds: number;
};

/** What a person lets an agent do in a tenant, and for how long. */
export type DelegateInput = {
	readonly tenant: string;
	/** Names the agent. Revoking the agent in the tenant revokes every delegation to it there. */
	readonly agent: string;
	readonly timeToLive: Duration;
	/**
	 * Ties the delegation to the session it was made from, so that signing out
	 * of the session or the device stops the agent. Without it the agent
	 * outlives the session, as an OAuth grant does, until the delegation, the
	 * agent, the subject or the tenant is revoked.
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
	readonly account: string;
	readonly tenant: string;
	/** The person the agent acts for, in the tenant. */
	readonly subject: string;
	readonly agent: string;
	readonly delegation: string;
	/** The device and session the delegation is tied to, or undefined when it is not. */
	readonly boundTo:
		| { readonly device: string; readonly session: string }
		| undefined;
	readonly delegatedAtMilliseconds: number;
};

/** An account session as a sign in reads it back: the grant, its proofs and the store's time. */
export type OpenSession = {
	readonly session: StoredGrant;
	readonly entry: StoredGrant | undefined;
	readonly proofs: readonly Proof[];
	readonly now: number;
};

/** What grants need. */
export type GrantsOptions = {
	readonly store: GrantStore;
	readonly records: Records;
	/** How long a session lives without being used; each use moves the end forward. */
	readonly idleMilliseconds: number;
	/** How long any grant lives at most, whatever happens. */
	readonly maximumMilliseconds: number;
	readonly audit?: AuditSink | undefined;
};

const tokenOf = (prefix: string): string => prefix + generateSecret();

const looksLike = (token: unknown, prefix: string): token is string =>
	typeof token === "string" &&
	token.startsWith(prefix) &&
	TOKEN_BODY.test(token.slice(prefix.length));

const parseProofs = (raw: string | undefined): readonly Proof[] | undefined => {
	const texts = raw === undefined ? undefined : safeParseJson(raw);

	if (!Array.isArray(texts) || texts.length === 0) {
		return undefined;
	}

	const proofs: Proof[] = [];

	for (const text of texts) {
		const restored = typeof text === "string" ? restoreProof(text) : undefined;

		if (restored === undefined || !restored.ok) {
			return undefined;
		}

		proofs.push(restored.value);
	}

	return proofs;
};

const alive = (grant: StoredGrant, now: number): boolean =>
	!grant.revoked &&
	now < grant.expiresAtMilliseconds &&
	(grant.idleExpiresAtMilliseconds === undefined ||
		now < grant.idleExpiresAtMilliseconds);

/**
 * Creates the grants: account sessions, their entries into tenants, and
 * agents. A bearer token is 256 random bits behind a prefix that names its
 * kind, `vas_` for a session and `vag_` for an agent; the store keeps only
 * its SHA-256, so a copy of the database opens nothing. Every grant read is
 * checked against its seal, so a grant written past the engine, for a token
 * someone knows the hash of, opens nothing either. A session ends when it was
 * not used for the idle time, and in any case at its end; each use moves the
 * idle end forward, writing to the store only when half of the idle time has
 * gone by. Every rejection reports the same `invalid-session` error; the audit
 * records why. Issuing and delegating are recorded before the grant is made,
 * so a failing sink means no grant; a revocation through `revoke` is made
 * first and recorded after.
 */
export function createGrants(options: GrantsOptions) {
	const { store, records, idleMilliseconds, maximumMilliseconds } = options;
	const audit = own(options, "audit");

	for (const [name, value] of [
		["idleMilliseconds", idleMilliseconds],
		["maximumMilliseconds", maximumMilliseconds],
	] as const) {
		if (!Number.isSafeInteger(value) || value <= 0) {
			throw new RangeError(`${name} must be a positive whole number`);
		}
	}

	if (idleMilliseconds > maximumMilliseconds) {
		throw new RangeError(
			"idleMilliseconds must be at most maximumMilliseconds",
		);
	}

	const refuse = async (
		reason: string,
		tenant: string,
		subject: string,
		detail: Readonly<Record<string, string>> = {},
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

	const reasonOf = (grant: StoredGrant): string =>
		grant.revoked ? AUDIT_REASONS.revoked : AUDIT_REASONS.expired;

	const open = async (
		token: string,
		tenant: string | undefined,
	): Promise<Result<OpenSession>> => {
		if (!looksLike(token, SESSION_PREFIX)) {
			return refuse(AUDIT_REASONS.malformed, tenant ?? "", "");
		}

		const reading = await store.findSession(await hashSecret(token), tenant);

		if (reading === undefined) {
			return refuse(AUDIT_REASONS.notFound, tenant ?? "", "");
		}

		const { session, entry, now } = reading;

		if (
			session.kind !== "session" ||
			(await records.checkGrant(session)) === "invalid"
		) {
			return refuse(AUDIT_REASONS.invalidRecord, tenant ?? "", "", {
				grant: "session",
			});
		}

		if (!alive(session, now)) {
			return refuse(reasonOf(session), tenant ?? "", "", {
				session: session.id,
				scope: "session",
			});
		}

		const proofs = parseProofs(session.proofs);

		if (proofs === undefined) {
			return refuse(AUDIT_REASONS.malformed, tenant ?? "", "", {
				session: session.id,
			});
		}

		if (
			entry !== undefined &&
			(entry.kind !== "tenant" ||
				entry.sessionId !== session.id ||
				entry.tenant !== tenant ||
				entry.accountId !== session.accountId ||
				(await records.checkGrant(entry)) === "invalid")
		) {
			return refuse(AUDIT_REASONS.invalidRecord, tenant ?? "", "", {
				grant: "tenant",
			});
		}

		const idleEnd = session.idleExpiresAtMilliseconds;

		if (idleEnd !== undefined && idleEnd - now < idleMilliseconds / 2) {
			await store.extendSession(
				session.id,
				Math.min(now + idleMilliseconds, session.expiresAtMilliseconds),
			);
		}

		return succeed({ session, entry, proofs, now });
	};

	const verify = async (
		token: string,
		tenant: string,
	): Promise<Result<VerifiedSession>> => {
		if (!isStorableText(tenant)) {
			return refuse(AUDIT_REASONS.malformed, "", "");
		}

		const opened = await open(token, tenant);

		if (!opened.ok) {
			return opened;
		}

		const { session, entry, proofs, now } = opened.value;

		if (entry === undefined || entry.subjectId === undefined) {
			return refuse(AUDIT_REASONS.notFound, tenant, "", {
				session: session.id,
				grant: "tenant",
			});
		}

		if (entry.revoked) {
			return refuse(AUDIT_REASONS.revoked, tenant, entry.subjectId, {
				session: session.id,
				scope: "tenant",
			});
		}

		return succeed({
			account: session.accountId,
			tenant,
			subject: entry.subjectId,
			device: session.device ?? "",
			session: session.id,
			methods: proofs.map((proof) => proof.factor),
			authenticatedAtMilliseconds: session.authenticatedAtMilliseconds,
			authenticationAgeMilliseconds: Math.max(
				0,
				now - session.authenticatedAtMilliseconds,
			),
		});
	};

	const revokeRecorded = async (level: RevocationLevel): Promise<void> => {
		const marked = await store.revoke(level);

		await report(audit, {
			event: AUDIT_EVENTS.sessionRevoke,
			outcome: AUDIT_OUTCOMES.success,
			reason: AUDIT_REASONS.revoked,
			tenant: "tenant" in level ? level.tenant : "",
			subject: level.scope === "subject" ? level.id : "",
			detail: {
				scope: level.scope,
				...("id" in level ? { id: level.id } : {}),
				grants: String(marked),
			},
		});
	};

	const entryOf = (
		session: StoredGrant,
		tenant: string,
		subjectId: string,
	): Promise<StoredGrant> =>
		records.grant({
			id: generateSecret(),
			kind: "tenant",
			tokenHash: undefined,
			accountId: session.accountId,
			tenant,
			subjectId,
			device: session.device,
			agent: undefined,
			parentId: session.id,
			sessionId: session.id,
			proofs: undefined,
			authenticatedAtMilliseconds: session.authenticatedAtMilliseconds,
			expiresAtMilliseconds: session.expiresAtMilliseconds,
			idleExpiresAtMilliseconds: undefined,
			revoked: false,
		});

	return {
		/**
		 * Creates the account session of a sign in with its entry into the
		 * tenant, and answers its token. Only a session born from an allow
		 * decision gets one.
		 */
		async issue(
			session: Session,
			input: IssueSessionInput,
		): Promise<Result<string>> {
			if (!isBornSession(session)) {
				return fail(ERROR_CODES.noSession);
			}

			await report(audit, {
				event: AUDIT_EVENTS.sessionIssue,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.issued,
				tenant: input.tenant,
				subject: input.subjectId,
				detail: {
					account: input.accountId,
					device: input.device,
					session: session.id,
				},
			});

			const now = await store.now();
			const token = tokenOf(SESSION_PREFIX);
			const expires = now + maximumMilliseconds;
			const root = await records.grant({
				id: session.id,
				kind: "session",
				tokenHash: await hashSecret(token),
				accountId: input.accountId,
				tenant: undefined,
				subjectId: undefined,
				device: input.device,
				agent: undefined,
				parentId: undefined,
				sessionId: undefined,
				proofs: JSON.stringify(input.proofs.map(serializeProof)),
				authenticatedAtMilliseconds: now,
				expiresAtMilliseconds: expires,
				idleExpiresAtMilliseconds: Math.min(now + idleMilliseconds, expires),
				revoked: false,
			});

			await store.createSession(
				root,
				await entryOf(root, input.tenant, input.subjectId),
			);

			return succeed(token);
		},
		verify,
		open,
		/**
		 * Adds an entry into a tenant to a live session. `conflict` when the
		 * session has a live entry into it already.
		 */
		async enter(
			session: StoredGrant,
			tenant: string,
			subjectId: string,
		): Promise<Result<StoredGrant>> {
			const entry = await entryOf(session, tenant, subjectId);

			return (await store.createGrant(entry)) === "created"
				? succeed(entry)
				: fail(ERROR_CODES.conflict);
		},
		/** Revokes a level for the application, and records it after. */
		revoke: revokeRecorded,
		/**
		 * Signs the holder of a session token out: of this session, of every
		 * session on its device, or of every session of the account. Answers
		 * whether the token was a live session.
		 */
		async end(
			token: string,
			level: "session" | "device" | "account" = "session",
		): Promise<boolean> {
			const opened = await open(token, undefined);

			if (!opened.ok) {
				return false;
			}

			const { session } = opened.value;

			await revokeRecorded(
				level === "account"
					? { scope: "account", id: session.accountId }
					: level === "device" && session.device !== undefined
						? { scope: "device", id: session.device }
						: { scope: "session", id: session.id },
			);

			return true;
		},
		/** Revokes a level as part of a change that records itself. */
		async revokeQuietly(level: RevocationLevel): Promise<void> {
			await store.revoke(level);
		},
		/** Deletes every grant of an account, for its deletion. */
		forget: (accountId: string): Promise<void> => store.forget(accountId),
		async delegate(
			sessionToken: string,
			input: DelegateInput,
		): Promise<Result<Delegation>> {
			const tenant = own(input, "tenant");
			const agent = own(input, "agent");
			const timeToLive = own(input, "timeToLive");

			if (
				!isStorableText(tenant) ||
				!isStorableText(agent) ||
				!isDuration(timeToLive) ||
				timeToLive.milliseconds > maximumMilliseconds
			) {
				return fail(ERROR_CODES.invalidRequest);
			}

			const delegator = await open(sessionToken, tenant);

			if (!delegator.ok) {
				return fail(ERROR_CODES.invalidSession);
			}

			const { session, entry, now } = delegator.value;

			if (
				entry === undefined ||
				entry.revoked ||
				entry.subjectId === undefined
			) {
				return fail(ERROR_CODES.invalidSession);
			}

			const bound = own(input, "boundToSession") === true;
			const delegation = generateSecret();

			await report(audit, {
				event: AUDIT_EVENTS.delegationGrant,
				outcome: AUDIT_OUTCOMES.success,
				reason: AUDIT_REASONS.issued,
				tenant,
				subject: entry.subjectId,
				detail: { agent, delegation, bound: String(bound) },
			});

			const token = tokenOf(AGENT_PREFIX);
			const expires = now + timeToLive.milliseconds;
			const granted = await store.createGrant(
				await records.grant({
					id: delegation,
					kind: "agent",
					tokenHash: await hashSecret(token),
					accountId: session.accountId,
					tenant,
					subjectId: entry.subjectId,
					device: bound ? session.device : undefined,
					agent,
					parentId: bound ? entry.id : undefined,
					sessionId: bound ? session.id : undefined,
					proofs: undefined,
					authenticatedAtMilliseconds: now,
					expiresAtMilliseconds: bound
						? Math.min(expires, session.expiresAtMilliseconds)
						: expires,
					idleExpiresAtMilliseconds: undefined,
					revoked: false,
				}),
			);

			return granted === "created"
				? succeed({ token, delegation })
				: fail(ERROR_CODES.conflict);
		},
		async verifyAgent(token: string): Promise<Result<VerifiedAgent>> {
			if (!looksLike(token, AGENT_PREFIX)) {
				return refuse(AUDIT_REASONS.malformed, "", "");
			}

			const reading = await store.findAgent(await hashSecret(token));

			if (reading === undefined) {
				return refuse(AUDIT_REASONS.notFound, "", "");
			}

			const { agent, session, now } = reading;
			const tenant = agent.tenant ?? "";
			const subject = agent.subjectId ?? "";

			if (
				agent.kind !== "agent" ||
				agent.agent === undefined ||
				agent.tenant === undefined ||
				agent.subjectId === undefined ||
				(await records.checkGrant(agent)) === "invalid"
			) {
				return refuse(AUDIT_REASONS.invalidRecord, tenant, subject, {
					grant: "agent",
				});
			}

			const detail = { agent: agent.agent, delegation: agent.id };

			if (!alive(agent, now)) {
				return refuse(reasonOf(agent), tenant, subject, {
					...detail,
					scope: "delegation",
				});
			}

			if (agent.sessionId !== undefined) {
				if (
					session === undefined ||
					session.id !== agent.sessionId ||
					(await records.checkGrant(session)) === "invalid"
				) {
					return refuse(AUDIT_REASONS.invalidRecord, tenant, subject, {
						...detail,
						grant: "session",
					});
				}

				if (!alive(session, now)) {
					return refuse(reasonOf(session), tenant, subject, {
						...detail,
						scope: "session",
					});
				}
			}

			return succeed({
				account: agent.accountId,
				tenant: agent.tenant,
				subject: agent.subjectId,
				agent: agent.agent,
				delegation: agent.id,
				boundTo:
					agent.sessionId === undefined
						? undefined
						: { device: agent.device ?? "", session: agent.sessionId },
				delegatedAtMilliseconds: agent.authenticatedAtMilliseconds,
			});
		},
	};
}

export type Grants = ReturnType<typeof createGrants>;
