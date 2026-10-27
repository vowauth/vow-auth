/** What a grant is: a session of an account on a device, its entry into a tenant, or an agent acting in a tenant. */
export type GrantKind = "session" | "tenant" | "agent";

/**
 * One node of the tree of grants, the only source of truth about access. A
 * session is a root; an entry into a tenant hangs under its session; an
 * agent hangs under an entry when it is bound to the session, and under
 * nothing when it lives on its own, as an OAuth grant does.
 */
export type StoredGrant = {
	readonly id: string;
	readonly kind: GrantKind;
	/** SHA-256 of the bearer token, for a session and an agent; the token itself is never stored. */
	readonly tokenHash: string | undefined;
	readonly accountId: string;
	readonly tenant: string | undefined;
	readonly subjectId: string | undefined;
	/** The device of the session, kept on everything bound to it. */
	readonly device: string | undefined;
	readonly agent: string | undefined;
	readonly parentId: string | undefined;
	/** The session at the root, for everything bound to one. */
	readonly sessionId: string | undefined;
	/** The proofs of the sign in, as text, for a session. */
	readonly proofs: string | undefined;
	readonly authenticatedAtMilliseconds: number;
	/** The end of the grant whatever happens, by the store's clock. */
	readonly expiresAtMilliseconds: number;
	/** When an idle session ends; moved forward while it is used, never past the end. */
	readonly idleExpiresAtMilliseconds: number | undefined;
	/** Set by a revocation; not part of the seal, as it only takes access away. */
	readonly revoked: boolean;
	readonly seal: string;
};

/**
 * A session found by its token, with its entry into the tenant asked for, and
 * the store's time. The entry is the live one when there is one, and else
 * the latest revoked one, so a refusal can say why.
 */
export type SessionReading = {
	readonly session: StoredGrant;
	readonly entry: StoredGrant | undefined;
	readonly now: number;
};

/** An agent found by its token, with the session it is bound to, and the store's time. */
export type AgentReading = {
	readonly agent: StoredGrant;
	readonly session: StoredGrant | undefined;
	readonly now: number;
};

/** A level to revoke; each revokes its grants and everything under them. */
export type RevocationLevel =
	| { readonly scope: "session"; readonly id: string }
	| { readonly scope: "device"; readonly id: string }
	| { readonly scope: "account"; readonly id: string }
	| {
			readonly scope: "subject";
			readonly tenant: string;
			readonly id: string;
	  }
	| { readonly scope: "tenant"; readonly tenant: string }
	| { readonly scope: "agent"; readonly tenant: string; readonly id: string }
	| { readonly scope: "delegation"; readonly id: string };

/**
 * Storage port of grants. Time is the store's: `now` and every reading carry
 * its clock, so the clocks of the application servers never matter. A
 * revocation marks every grant of the level and all grants under them in one
 * atomic write, so a check reads only the grants it is given and never walks
 * the tree. An adapter must guarantee all of this.
 *
 * - `revoke` of `session` takes the session and every grant whose session it
 *   is; of `device` and `account`, every session of it with the same;
 *   of `subject`, the entries and agents of the subject in the tenant; of
 *   `tenant`, every grant in the tenant; of `agent`, every grant of that agent
 *   in the tenant; of `delegation`, that agent grant. It answers how many
 *   grants it marked, the already revoked included.
 * - A revoked grant stays revoked; nothing in the port clears the mark.
 * - `extendSession` never moves the idle end back, nor past the end.
 * - Strong consistency: a completed `revoke` is seen by every later read.
 * - Failures throw.
 */
export type GrantStore = {
	now(): Promise<number>;
	/** A session and its first entry into a tenant, at once. */
	createSession(session: StoredGrant, entry: StoredGrant): Promise<void>;
	/** An entry into a tenant or an agent; `conflict` when the session already has a live entry into that tenant. */
	createGrant(grant: StoredGrant): Promise<"created" | "conflict">;
	findSession(
		tokenHash: string,
		tenant: string | undefined,
	): Promise<SessionReading | undefined>;
	/** A session by its id, read as `findSession` reads it by its token; `undefined` when no session has this id. */
	getSession(
		id: string,
		tenant: string | undefined,
	): Promise<SessionReading | undefined>;
	findAgent(tokenHash: string): Promise<AgentReading | undefined>;
	extendSession(id: string, idleExpiresAtMilliseconds: number): Promise<void>;
	revoke(level: RevocationLevel): Promise<number>;
	/** Deletes every grant of the account, for its deletion: a session keeps the proofs of its sign in. */
	forget(accountId: string): Promise<void>;
};
