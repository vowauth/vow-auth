import type {
	AccountStore,
	MembershipStatus,
	StoredAccount,
	StoredIdentity,
	StoredMembership,
	StoredTenant,
} from "@vow-auth/core";
import {
	type PostgresRow,
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
	toText,
} from "./postgres-runner.js";

const GET_TENANT = `select id, disabled_at_milliseconds is not null as disabled, seal
	from vow_auth_tenants where id = $1`;

const CREATE_TENANT = `insert into vow_auth_tenants (id, disabled_at_milliseconds, seal)
	values ($1, case when $2::boolean then ${SERVER_NOW_MILLISECONDS} end, $3)
	on conflict (id) do nothing
	returning id`;

const SET_TENANT = `update vow_auth_tenants
	set disabled_at_milliseconds = case
			when $2::boolean then coalesce(disabled_at_milliseconds, ${SERVER_NOW_MILLISECONDS})
		end,
		seal = $3
	where id = $1 and seal = $4
	returning id`;

const IDENTITY_COLUMNS =
	"provider, external_id, account_id, email, email_verified, seal";

const FIND_IDENTITY = `select ${IDENTITY_COLUMNS} from vow_auth_identities
	where provider = $1 and external_id = $2`;

const VERIFIED_OWNER = `select ${IDENTITY_COLUMNS} from vow_auth_identities
	where email = $1 and email_verified and provider = any($2::text[])
	order by seq limit 1`;

const GET_ACCOUNT = `select id, managed_by_tenant,
		evicted_at_milliseconds is not null as evicted, seal
	from vow_auth_accounts where id = $1`;

const SET_ACCOUNT = `update vow_auth_accounts
	set managed_by_tenant = $2, seal = $3
	where id = $1 and seal = $4
	returning id`;

const MEMBERSHIP_COLUMNS = "id, tenant, account_id, status, seal";

const FIND_MEMBERSHIP = `select ${MEMBERSHIP_COLUMNS} from vow_auth_subjects
	where tenant = $1 and account_id = $2`;

const GET_MEMBERSHIP = `select ${MEMBERSHIP_COLUMNS} from vow_auth_subjects
	where tenant = $1 and id = $2`;

const LIST_MEMBERSHIPS = `select ${MEMBERSHIP_COLUMNS} from vow_auth_subjects
	where account_id = $1 order by created_at_milliseconds, id`;

const CREATE_ACCOUNT = `with identity as (
	insert into vow_auth_identities
		(provider, external_id, account_id, email, email_verified, seal)
	values ($4, $5, $1, $6, $7, $8)
	on conflict (provider, external_id) do nothing
	returning account_id
), account as (
	insert into vow_auth_accounts (id, managed_by_tenant, seal)
	select account_id, $2, $3 from identity
	returning id
), membership as (
	insert into vow_auth_subjects (id, tenant, account_id, status, seal)
	select $9, $10, id, $11, $12 from account where $9::text is not null
	returning id
)
select (select count(*) from account)::int as accounts`;

const LINK_IDENTITY = `insert into vow_auth_identities
	(provider, external_id, account_id, email, email_verified, seal)
select $1::text, $2::text, $3::text, $4::text, $5::boolean, $6::text
where exists (
	select 1 from vow_auth_accounts
	where id = $3 and evicted_at_milliseconds is null
)
on conflict (provider, external_id) do nothing
returning account_id`;

const UPDATE_IDENTITY = `update vow_auth_identities
	set email = $4, email_verified = $5, seal = $6,
		updated_at_milliseconds = ${SERVER_NOW_MILLISECONDS}
	where provider = $1 and external_id = $2 and account_id = $3 and seal = $7
	returning account_id`;

const CREATE_MEMBERSHIP = `insert into vow_auth_subjects (id, tenant, account_id, status, seal)
select $1::text, $2::text, $3::text, $4::text, $5::text
where exists (
	select 1 from vow_auth_accounts
	where id = $3 and evicted_at_milliseconds is null
)
on conflict do nothing
returning id`;

const SET_MEMBERSHIP = `update vow_auth_subjects
	set status = $4, seal = $5
	where id = $1 and tenant = $2 and account_id is not distinct from $3 and seal = $6
	returning id`;

const CLAIMS = `email = $1 and account_id <> $2
	and not (email_verified and provider = any($3::text[]))`;

const EMAIL_CLAIMANTS = `select account_id from vow_auth_identities
	where ${CLAIMS}
	group by account_id order by min(seq)`;

const EVICT_EMAIL_CLAIMS = `with removed as (
	delete from vow_auth_identities
	where ${CLAIMS}
	returning account_id, seq
), touched as (
	select account_id, min(seq) as first from removed group by account_id
), evicted as (
	update vow_auth_accounts as account
	set evicted_at_milliseconds = ${SERVER_NOW_MILLISECONDS}
	where account.evicted_at_milliseconds is null
		and account.id in (select account_id from touched)
		and not exists (
			select 1 from vow_auth_identities as kept
			where kept.account_id = account.id
				and (kept.email is distinct from $1
					or (kept.email_verified and kept.provider = any($3::text[])))
		)
)
select account_id from touched order by first`;

const DELETE_ACCOUNT = `with orphaned as (
	update vow_auth_subjects
	set account_id = null, status = 'removed'
	where account_id = $1
	returning id, tenant, seal
), deleted as (
	delete from vow_auth_accounts where id = $1 returning id
)
select orphaned.id, orphaned.tenant, orphaned.seal
from deleted left join orphaned on true`;

const UNIQUE_VIOLATION = "23505";
const FOREIGN_KEY_VIOLATION = "23503";

const isViolation = (error: unknown): boolean =>
	typeof error === "object" &&
	error !== null &&
	"code" in error &&
	(error.code === UNIQUE_VIOLATION || error.code === FOREIGN_KEY_VIOLATION);

const optionalText = (value: unknown): string | undefined =>
	value === null || value === undefined ? undefined : toText(value);

const toBoolean = (value: unknown): boolean => {
	if (typeof value !== "boolean") {
		throw new Error("The database must answer a boolean column with a boolean");
	}

	return value;
};

const STATUSES: readonly MembershipStatus[] = [
	"active",
	"suspended",
	"removed",
];

const toStatus = (value: unknown): MembershipStatus => {
	const status = STATUSES.find((candidate) => candidate === value);

	if (status === undefined) {
		throw new Error("The database answered a membership status it cannot hold");
	}

	return status;
};

const tenantOf = (row: PostgresRow): StoredTenant => ({
	id: toText(row.id),
	disabled: toBoolean(row.disabled),
	seal: toText(row.seal),
});

const accountOf = (row: PostgresRow): StoredAccount => ({
	id: toText(row.id),
	managedByTenant: optionalText(row.managed_by_tenant),
	evicted: toBoolean(row.evicted),
	seal: toText(row.seal),
});

const identityOf = (row: PostgresRow): StoredIdentity => ({
	provider: toText(row.provider),
	externalId: toText(row.external_id),
	accountId: toText(row.account_id),
	email: optionalText(row.email),
	emailVerified: toBoolean(row.email_verified),
	seal: toText(row.seal),
});

const membershipOf = (row: PostgresRow): StoredMembership => ({
	subjectId: toText(row.id),
	tenant: toText(row.tenant),
	accountId: optionalText(row.account_id),
	status: toStatus(row.status),
	seal: toText(row.seal),
});

/**
 * Account store on Postgres. Every method is one statement, so each is atomic
 * on its own, and a runner bound to a transaction makes them part of it. The
 * primary key of an identity is `(provider, external_id)` and a membership is
 * unique for `(tenant, account_id)`; a conflict on either leaves the rows as
 * they are and the call says so. Creating an account inserts its identity
 * first and the account only when the identity went in, so a conflict leaves
 * no account behind; any other violation, such as a tenant that does not
 * exist, rolls the statement back and counts as a conflict. Compare-and-set
 * updates match the seal the caller read. Removing the unverified claims of
 * an email and marking the emptied accounts evicted is one statement, so it
 * cannot stop half way. Deleting an account takes its identities with it and
 * leaves its subjects without an account and removed.
 */
export function createPostgresAccountStore(run: PostgresRunner): AccountStore {
	const tolerant = async (
		statement: string,
		parameters: readonly unknown[],
	): Promise<readonly PostgresRow[] | undefined> => {
		try {
			return await run(statement, parameters);
		} catch (error) {
			if (isViolation(error)) {
				return undefined;
			}

			throw error;
		}
	};

	const one = async <Record>(
		statement: string,
		parameters: readonly unknown[],
		read: (row: PostgresRow) => Record,
	): Promise<Record | undefined> => {
		const [row] = await run(statement, parameters);

		return row === undefined ? undefined : read(row);
	};

	const findIdentity = (provider: string, externalId: string) =>
		one(FIND_IDENTITY, [provider, externalId], identityOf);

	return {
		getTenant: (id) => one(GET_TENANT, [id], tenantOf),
		async createTenant(tenant) {
			const rows = await run(CREATE_TENANT, [
				tenant.id,
				tenant.disabled,
				tenant.seal,
			]);

			return rows.length > 0 ? "created" : "conflict";
		},
		async setTenant(tenant, expectedSeal) {
			const rows = await run(SET_TENANT, [
				tenant.id,
				tenant.disabled,
				tenant.seal,
				expectedSeal,
			]);

			return rows.length > 0;
		},
		findIdentity,
		findVerifiedOwner: (email, providers) =>
			one(VERIFIED_OWNER, [email, [...providers]], identityOf),
		getAccount: (id) => one(GET_ACCOUNT, [id], accountOf),
		async setAccount(account, expectedSeal) {
			const rows = await run(SET_ACCOUNT, [
				account.id,
				account.managedByTenant ?? null,
				account.seal,
				expectedSeal,
			]);

			return rows.length > 0;
		},
		findMembership: (tenant, accountId) =>
			one(FIND_MEMBERSHIP, [tenant, accountId], membershipOf),
		getMembership: (tenant, subjectId) =>
			one(GET_MEMBERSHIP, [tenant, subjectId], membershipOf),
		async listMemberships(accountId) {
			return (await run(LIST_MEMBERSHIPS, [accountId])).map(membershipOf);
		},
		async createAccount(account, identity, membership) {
			const rows = await tolerant(CREATE_ACCOUNT, [
				account.id,
				account.managedByTenant ?? null,
				account.seal,
				identity.provider,
				identity.externalId,
				identity.email ?? null,
				identity.emailVerified,
				identity.seal,
				membership?.subjectId ?? null,
				membership?.tenant ?? null,
				membership?.status ?? null,
				membership?.seal ?? null,
			]);
			const [row] = rows ?? [];

			return row !== undefined && Number(row.accounts) === 1
				? "created"
				: "conflict";
		},
		async linkIdentity(identity) {
			const rows = await tolerant(LINK_IDENTITY, [
				identity.provider,
				identity.externalId,
				identity.accountId,
				identity.email ?? null,
				identity.emailVerified,
				identity.seal,
			]);

			if (rows !== undefined && rows.length > 0) {
				return "linked";
			}

			return (await findIdentity(identity.provider, identity.externalId)) ===
				undefined
				? "missing"
				: "conflict";
		},
		async updateIdentity(identity, expectedSeal) {
			const rows = await run(UPDATE_IDENTITY, [
				identity.provider,
				identity.externalId,
				identity.accountId,
				identity.email ?? null,
				identity.emailVerified,
				identity.seal,
				expectedSeal,
			]);

			return rows.length > 0;
		},
		async createMembership(membership) {
			const rows = await tolerant(CREATE_MEMBERSHIP, [
				membership.subjectId,
				membership.tenant,
				membership.accountId ?? null,
				membership.status,
				membership.seal,
			]);

			return rows !== undefined && rows.length > 0 ? "created" : "conflict";
		},
		async setMembership(membership, expectedSeal) {
			const rows = await run(SET_MEMBERSHIP, [
				membership.subjectId,
				membership.tenant,
				membership.accountId ?? null,
				membership.status,
				membership.seal,
				expectedSeal,
			]);

			return rows.length > 0;
		},
		async findEmailClaimants(email, keepAccountId, trustedProviders) {
			const rows = await run(EMAIL_CLAIMANTS, [
				email,
				keepAccountId,
				[...trustedProviders],
			]);

			return rows.map((row) => toText(row.account_id));
		},
		async evictEmailClaims(email, keepAccountId, trustedProviders) {
			const rows = await run(EVICT_EMAIL_CLAIMS, [
				email,
				keepAccountId,
				[...trustedProviders],
			]);

			return rows.map((row) => toText(row.account_id));
		},
		async deleteAccount(id) {
			const rows = await run(DELETE_ACCOUNT, [id]);

			if (rows.length === 0) {
				return undefined;
			}

			return rows
				.filter((row) => row.id !== null && row.id !== undefined)
				.map(
					(row): StoredMembership => ({
						subjectId: toText(row.id),
						tenant: toText(row.tenant),
						accountId: undefined,
						status: "removed",
						seal: toText(row.seal),
					}),
				);
		},
	};
}
