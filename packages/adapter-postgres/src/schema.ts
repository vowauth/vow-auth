import {
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
} from "./postgres-runner.js";

/**
 * The statements that create the tables of the Postgres stores, one by one,
 * for clients that run a single statement per call. Every statement can be
 * run again: it does nothing when its table or index exists. The data of the
 * application points at a person with a foreign key to
 * `vow_auth_subjects (id)`; the id is unique across tenants. A subject is never
 * deleted behind the back of the application: an eviction only sets
 * `evicted_at_milliseconds`, and the `on delete` rule of the foreign key of the
 * application decides what an explicit deletion does to its rows.
 */
export const POSTGRES_SCHEMA_STATEMENTS: readonly string[] = [
	`create table if not exists vow_auth_subjects (
	id text primary key,
	tenant text not null,
	created_at_milliseconds bigint not null default ${SERVER_NOW_MILLISECONDS},
	evicted_at_milliseconds bigint,
	unique (tenant, id)
)`,
	`create table if not exists vow_auth_identities (
	seq bigserial not null,
	tenant text not null,
	provider text not null,
	external_id text not null,
	subject_id text not null,
	email text,
	email_verified boolean not null,
	primary key (tenant, provider, external_id),
	foreign key (tenant, subject_id)
		references vow_auth_subjects (tenant, id) on delete cascade
)`,
	`create index if not exists vow_auth_identities_subject
	on vow_auth_identities (tenant, subject_id)`,
	`create index if not exists vow_auth_identities_email
	on vow_auth_identities (tenant, email, seq) where email is not null`,
	`create table if not exists vow_auth_tokens (
	hash text primary key,
	purpose text not null,
	payload text not null,
	expires_at_milliseconds bigint not null
)`,
	`create index if not exists vow_auth_tokens_expiry
	on vow_auth_tokens (expires_at_milliseconds)`,
	`create table if not exists vow_auth_outbox (
	seq bigserial primary key,
	id text not null unique,
	type text not null,
	payload text not null,
	attempts integer not null default 0,
	available_at_milliseconds bigint not null default 0
)`,
	`create index if not exists vow_auth_outbox_available
	on vow_auth_outbox (available_at_milliseconds, seq)`,
	`create table if not exists vow_auth_outbox_buried (
	seq bigserial primary key,
	id text not null,
	type text not null,
	payload text not null,
	attempts integer not null,
	buried_at_milliseconds bigint not null
)`,
];

/** The same statements as one text, to paste into the migration of the application. */
export const POSTGRES_SCHEMA = `${POSTGRES_SCHEMA_STATEMENTS.join(";\n\n")};\n`;

/** Creates the tables with a runner; safe to run again. */
export async function createPostgresSchema(run: PostgresRunner): Promise<void> {
	for (const statement of POSTGRES_SCHEMA_STATEMENTS) {
		await run(statement, []);
	}
}
