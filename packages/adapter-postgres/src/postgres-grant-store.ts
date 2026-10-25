import type {
	GrantKind,
	GrantStore,
	RevocationLevel,
	StoredGrant,
} from "@vow-auth/core";
import {
	type PostgresRow,
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
	toNumber,
	toText,
} from "./postgres-runner.js";

const COLUMNS = [
	"id",
	"kind",
	"token_hash",
	"account_id",
	"tenant",
	"subject_id",
	"device",
	"agent",
	"parent_id",
	"session_id",
	"proofs",
	"authenticated_at_milliseconds",
	"expires_at_milliseconds",
	"idle_expires_at_milliseconds",
] as const;

const columnsOf = (alias: string): string =>
	[
		...COLUMNS.map((column) => `${alias}.${column} as ${alias}_${column}`),
		`${alias}.revoked_at_milliseconds is not null as ${alias}_revoked`,
		`${alias}.seal as ${alias}_seal`,
	].join(", ");

const GRANT_COLUMNS = columnsOf("g");
const ENTRY_COLUMNS = columnsOf("e");
const SESSION_COLUMNS = columnsOf("s");

const INSERT_COLUMNS = [...COLUMNS, "seal"].join(", ");

const NOW = `select ${SERVER_NOW_MILLISECONDS} as now`;

const INSERT_TWO = `insert into vow_auth_grants (${INSERT_COLUMNS})
	values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15),
		($16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)`;

const INSERT_ONE = `insert into vow_auth_grants (${INSERT_COLUMNS})
	values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	on conflict do nothing
	returning id`;

const FIND_SESSION = `select ${GRANT_COLUMNS}, ${ENTRY_COLUMNS}, ${SERVER_NOW_MILLISECONDS} as now
	from vow_auth_grants as g
	left join lateral (
		select * from vow_auth_grants as candidate
		where candidate.kind = 'tenant' and candidate.session_id = g.id
			and candidate.tenant = $2
		order by (candidate.revoked_at_milliseconds is null) desc,
			candidate.created_at_milliseconds desc
		limit 1
	) as e on true
	where g.token_hash = $1`;

const FIND_AGENT = `select ${GRANT_COLUMNS}, ${SESSION_COLUMNS}, ${SERVER_NOW_MILLISECONDS} as now
	from vow_auth_grants as g
	left join vow_auth_grants as s on s.id = g.session_id
	where g.token_hash = $1`;

const EXTEND = `update vow_auth_grants
	set idle_expires_at_milliseconds = least(
		greatest(coalesce(idle_expires_at_milliseconds, $2), $2),
		expires_at_milliseconds
	)
	where id = $1`;

const REVOKE = `update vow_auth_grants
	set revoked_at_milliseconds = coalesce(revoked_at_milliseconds, ${SERVER_NOW_MILLISECONDS})
	where`;

const REVOKE_SESSION = `${REVOKE} id = $1 or session_id = $1 returning id`;
const REVOKE_DEVICE = `${REVOKE} device = $1 returning id`;
const REVOKE_ACCOUNT = `${REVOKE} account_id = $1
	and (kind = 'session' or session_id is not null) returning id`;
const REVOKE_SUBJECT = `${REVOKE} tenant = $1 and subject_id = $2 returning id`;
const REVOKE_TENANT = `${REVOKE} tenant = $1 returning id`;
const REVOKE_AGENT = `${REVOKE} kind = 'agent' and tenant = $1 and agent = $2 returning id`;
const REVOKE_DELEGATION = `${REVOKE} kind = 'agent' and id = $1 returning id`;

const FORGET = "delete from vow_auth_grants where account_id = $1";

const KINDS: readonly GrantKind[] = ["session", "tenant", "agent"];

const UNIQUE_VIOLATION = "23505";
const FOREIGN_KEY_VIOLATION = "23503";

const isViolation = (error: unknown): boolean =>
	typeof error === "object" &&
	error !== null &&
	"code" in error &&
	(error.code === UNIQUE_VIOLATION || error.code === FOREIGN_KEY_VIOLATION);

const optionalText = (value: unknown): string | undefined =>
	value === null || value === undefined ? undefined : toText(value);

const optionalNumber = (value: unknown): number | undefined =>
	value === null || value === undefined ? undefined : toNumber(value);

const valuesOf = (grant: StoredGrant): readonly unknown[] => [
	grant.id,
	grant.kind,
	grant.tokenHash ?? null,
	grant.accountId,
	grant.tenant ?? null,
	grant.subjectId ?? null,
	grant.device ?? null,
	grant.agent ?? null,
	grant.parentId ?? null,
	grant.sessionId ?? null,
	grant.proofs ?? null,
	grant.authenticatedAtMilliseconds,
	grant.expiresAtMilliseconds,
	grant.idleExpiresAtMilliseconds ?? null,
	grant.seal,
];

const grantOf = (row: PostgresRow, alias: string): StoredGrant | undefined => {
	const at = (column: string): unknown => row[`${alias}_${column}`];

	if (at("id") === null || at("id") === undefined) {
		return undefined;
	}

	const kind = KINDS.find((candidate) => candidate === at("kind"));

	if (kind === undefined) {
		throw new Error("The database answered a grant kind it cannot hold");
	}

	return {
		id: toText(at("id")),
		kind,
		tokenHash: optionalText(at("token_hash")),
		accountId: toText(at("account_id")),
		tenant: optionalText(at("tenant")),
		subjectId: optionalText(at("subject_id")),
		device: optionalText(at("device")),
		agent: optionalText(at("agent")),
		parentId: optionalText(at("parent_id")),
		sessionId: optionalText(at("session_id")),
		proofs: optionalText(at("proofs")),
		authenticatedAtMilliseconds: toNumber(at("authenticated_at_milliseconds")),
		expiresAtMilliseconds: toNumber(at("expires_at_milliseconds")),
		idleExpiresAtMilliseconds: optionalNumber(
			at("idle_expires_at_milliseconds"),
		),
		revoked: at("revoked") === true,
		seal: toText(at("seal")),
	};
};

const revocationOf = (
	level: RevocationLevel,
): readonly [string, readonly unknown[]] => {
	switch (level.scope) {
		case "session":
			return [REVOKE_SESSION, [level.id]];
		case "device":
			return [REVOKE_DEVICE, [level.id]];
		case "account":
			return [REVOKE_ACCOUNT, [level.id]];
		case "subject":
			return [REVOKE_SUBJECT, [level.tenant, level.id]];
		case "tenant":
			return [REVOKE_TENANT, [level.tenant]];
		case "agent":
			return [REVOKE_AGENT, [level.tenant, level.id]];
		case "delegation":
			return [REVOKE_DELEGATION, [level.id]];
	}
};

/**
 * Grant store on Postgres. Every method is one statement. A session and its
 * first entry go in together; an entry is unique for a session and a tenant
 * among the live ones, by a partial unique index, so a revoked entry leaves
 * room for a new one. A session is read with its entry, and an agent with its
 * session, by one query that also carries the server's clock. A revocation
 * is one update that sets the mark once and never clears it; the device and
 * the root session kept on every grant bound to a session make each level a
 * plain condition, so no level walks the tree. The times are the server's.
 */
export function createPostgresGrantStore(run: PostgresRunner): GrantStore {
	return {
		async now() {
			const [row] = await run(NOW, []);

			return toNumber(row?.now);
		},
		async createSession(session, entry) {
			await run(INSERT_TWO, [...valuesOf(session), ...valuesOf(entry)]);
		},
		async createGrant(grant) {
			try {
				const rows = await run(INSERT_ONE, valuesOf(grant));

				return rows.length > 0 ? "created" : "conflict";
			} catch (error) {
				if (isViolation(error)) {
					return "conflict";
				}

				throw error;
			}
		},
		async findSession(tokenHash, tenant) {
			const [row] = await run(FIND_SESSION, [tokenHash, tenant ?? null]);
			const session = row === undefined ? undefined : grantOf(row, "g");

			if (row === undefined || session === undefined) {
				return undefined;
			}

			return { session, entry: grantOf(row, "e"), now: toNumber(row.now) };
		},
		async findAgent(tokenHash) {
			const [row] = await run(FIND_AGENT, [tokenHash]);
			const agent = row === undefined ? undefined : grantOf(row, "g");

			if (row === undefined || agent === undefined) {
				return undefined;
			}

			return { agent, session: grantOf(row, "s"), now: toNumber(row.now) };
		},
		async extendSession(id, idleExpiresAtMilliseconds) {
			await run(EXTEND, [id, idleExpiresAtMilliseconds]);
		},
		async revoke(level) {
			const [statement, parameters] = revocationOf(level);

			return (await run(statement, parameters)).length;
		},
		async forget(accountId) {
			await run(FORGET, [accountId]);
		},
	};
}
