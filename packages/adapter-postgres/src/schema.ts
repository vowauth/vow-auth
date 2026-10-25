import {
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
} from "./postgres-runner.js";

/**
 * The statements that create the tables of the Postgres stores, one by one,
 * for clients that run a single statement per call. Every statement can be
 * run again: it does nothing when its table or index exists. The data of the
 * application points at a person in a tenant with a foreign key to
 * `vow_auth_subjects (id)`. A subject is never deleted behind the back of the
 * application: removing it from the tenant only changes its status, and
 * deleting its account leaves it without one. Grants keep the ids of accounts,
 * tenants and subjects without foreign keys, so they can live in another
 * store; the engine deletes the grants of an account it deletes.
 */
export const POSTGRES_SCHEMA_STATEMENTS: readonly string[] = [
	`create table if not exists vow_auth_tenants (
	id text primary key,
	created_at_milliseconds bigint not null default ${SERVER_NOW_MILLISECONDS},
	disabled_at_milliseconds bigint,
	seal text not null
)`,
	`create table if not exists vow_auth_accounts (
	id text primary key,
	managed_by_tenant text references vow_auth_tenants (id),
	created_at_milliseconds bigint not null default ${SERVER_NOW_MILLISECONDS},
	evicted_at_milliseconds bigint,
	seal text not null
)`,
	`create table if not exists vow_auth_identities (
	seq bigserial not null,
	provider text not null,
	external_id text not null,
	account_id text not null references vow_auth_accounts (id) on delete cascade,
	email text,
	email_verified boolean not null,
	updated_at_milliseconds bigint not null default ${SERVER_NOW_MILLISECONDS},
	seal text not null,
	primary key (provider, external_id)
)`,
	`create index if not exists vow_auth_identities_account
	on vow_auth_identities (account_id)`,
	`create index if not exists vow_auth_identities_email
	on vow_auth_identities (email, seq) where email is not null`,
	`create table if not exists vow_auth_subjects (
	id text primary key,
	tenant text not null references vow_auth_tenants (id),
	account_id text references vow_auth_accounts (id) on delete set null,
	status text not null check (status in ('active', 'suspended', 'removed')),
	created_at_milliseconds bigint not null default ${SERVER_NOW_MILLISECONDS},
	seal text not null,
	unique (tenant, account_id)
)`,
	`create index if not exists vow_auth_subjects_account
	on vow_auth_subjects (account_id)`,
	`create table if not exists vow_auth_grants (
	id text primary key,
	kind text not null check (kind in ('session', 'tenant', 'agent')),
	token_hash text unique,
	account_id text not null,
	tenant text,
	subject_id text,
	device text,
	agent text,
	parent_id text references vow_auth_grants (id) on delete cascade,
	session_id text references vow_auth_grants (id) on delete cascade,
	proofs text,
	authenticated_at_milliseconds bigint not null,
	created_at_milliseconds bigint not null default ${SERVER_NOW_MILLISECONDS},
	expires_at_milliseconds bigint not null,
	idle_expires_at_milliseconds bigint,
	revoked_at_milliseconds bigint,
	seal text not null
)`,
	`create unique index if not exists vow_auth_grants_live_entry
	on vow_auth_grants (session_id, tenant)
	where kind = 'tenant' and revoked_at_milliseconds is null`,
	`create index if not exists vow_auth_grants_session
	on vow_auth_grants (session_id)`,
	`create index if not exists vow_auth_grants_account
	on vow_auth_grants (account_id)`,
	`create index if not exists vow_auth_grants_subject
	on vow_auth_grants (tenant, subject_id)`,
	`create index if not exists vow_auth_grants_device
	on vow_auth_grants (device)`,
	`create index if not exists vow_auth_grants_agent
	on vow_auth_grants (tenant, agent) where kind = 'agent'`,
	`create table if not exists vow_auth_tokens (
	hash text primary key,
	purpose text not null,
	payload text not null,
	expires_at_milliseconds bigint not null
)`,
	`create index if not exists vow_auth_tokens_expiry
	on vow_auth_tokens (expires_at_milliseconds)`,
];

/** The same statements as one text, to paste into the migration of the application. */
export const POSTGRES_SCHEMA = `${POSTGRES_SCHEMA_STATEMENTS.join(";\n\n")};\n`;

/** Creates the tables with a runner; safe to run again. */
export async function createPostgresSchema(run: PostgresRunner): Promise<void> {
	for (const statement of POSTGRES_SCHEMA_STATEMENTS) {
		await run(statement, []);
	}
}
