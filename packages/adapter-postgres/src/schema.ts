import type { PostgresRunner } from "./postgres-runner.js";

/**
 * The statements that create the tables of the Postgres stores, one by one,
 * for clients that run a single statement per call. Every statement can be
 * run again: it does nothing when its table or index exists.
 */
export const POSTGRES_SCHEMA_STATEMENTS: readonly string[] = [
	`create table if not exists vow_auth_identities (
	seq bigserial not null,
	tenant text not null,
	provider text not null,
	external_id text not null,
	subject_id text not null,
	email text,
	email_verified boolean not null,
	primary key (tenant, provider, external_id)
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
