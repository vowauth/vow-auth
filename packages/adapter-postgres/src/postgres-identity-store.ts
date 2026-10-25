import type {
	CanonicalEmail,
	IdentityClaims,
	IdentityStore,
} from "@vow-auth/core";
import {
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
	toNumber,
	toText,
} from "./postgres-runner.js";

const MAXIMUM_ATTEMPTS = 3;

type Columns = readonly [string, string, string | null, boolean];

const columnsOf = (identity: IdentityClaims): Columns => [
	identity.provider,
	identity.externalId,
	identity.email?.address ?? null,
	identity.emailVerified,
];

const CREATE = `with identity as (
	insert into vow_auth_identities
		(tenant, provider, external_id, subject_id, email, email_verified)
	values ($1, $2, $3, $4, $5, $6)
	on conflict (tenant, provider, external_id) do nothing
	returning tenant, subject_id
)
insert into vow_auth_subjects (id, tenant)
select subject_id, tenant from identity
returning id`;

const LINK = `insert into vow_auth_identities
	(tenant, provider, external_id, subject_id, email, email_verified)
select $1::text, $2::text, $3::text, $4::text, $5::text, $6::boolean
where exists (
	select 1 from vow_auth_subjects
	where tenant = $1 and id = $4 and evicted_at_milliseconds is null
)
on conflict (tenant, provider, external_id) do nothing
returning subject_id`;

const OWNER = `select subject_id from vow_auth_identities
	where tenant = $1 and provider = $2 and external_id = $3`;

const VERIFIED_OWNER = `select subject_id from vow_auth_identities
	where tenant = $1 and email = $2 and email_verified
	order by seq limit 1`;

const UNVERIFIED_CLAIMANTS = `select subject_id from vow_auth_identities
	where tenant = $1 and email = $2 and not email_verified
	group by subject_id order by min(seq)`;

const SUBJECT = `select evicted_at_milliseconds from vow_auth_subjects
	where tenant = $1 and id = $2`;

const REMOVE_UNVERIFIED_CLAIMS = `with owner as (
	select subject_id from vow_auth_identities
	where tenant = $1 and email = $2 and email_verified
	order by seq limit 1
), claimants as (
	select distinct subject_id from vow_auth_identities
	where tenant = $1 and email = $2 and not email_verified
		and subject_id <> $3
		and subject_id not in (select subject_id from owner)
), removed as (
	delete from vow_auth_identities
	where tenant = $1 and email = $2 and not email_verified
		and subject_id in (select subject_id from claimants)
), evicted as (
	update vow_auth_subjects as subject
	set evicted_at_milliseconds = ${SERVER_NOW_MILLISECONDS}
	where subject.tenant = $1 and subject.evicted_at_milliseconds is null
		and subject.id in (select subject_id from claimants)
		and not exists (
			select 1 from vow_auth_identities as kept
			where kept.tenant = $1 and kept.subject_id = subject.id
				and (kept.email is distinct from $2 or kept.email_verified)
		)
)
select subject_id from claimants`;

const DELETE_SUBJECT = `delete from vow_auth_subjects
	where tenant = $1 and id = $2
	returning id`;

const FOREIGN_KEY_VIOLATION = "23503";

const isForeignKeyViolation = (error: unknown): boolean =>
	typeof error === "object" &&
	error !== null &&
	"code" in error &&
	error.code === FOREIGN_KEY_VIOLATION;

/**
 * Identity store on Postgres. A subject is a row of \`vow_auth_subjects\`, the
 * table the application points its foreign keys at, and its identities
 * reference it. The primary key \`(tenant, provider, external_id)\` makes
 * \`createSubject\` and \`linkIdentity\` atomic and first-wins: a conflict
 * leaves the existing row and the call answers its owner. \`createSubject\` is
 * one statement that inserts the subject only when its identity went in, so a
 * conflict leaves no subject behind; the foreign key is checked at the end of
 * the statement. \`linkIdentity\` inserts only into a subject that exists and
 * was not evicted; a subject deleted during the call counts as missing. The
 * owner of a verified email is the oldest identity that verified it, so
 * deleting the owner hands the email to the next one. Removing the unverified
 * claims of an email and marking the emptied subjects evicted is one
 * statement, so it cannot stop half way. Every method names the tenant in its
 * query.
 */
export function createPostgresIdentityStore(
	run: PostgresRunner,
): IdentityStore {
	const owner = async (
		tenant: string,
		provider: string,
		externalId: string,
	): Promise<string | undefined> => {
		const [row] = await run(OWNER, [tenant, provider, externalId]);

		return row === undefined ? undefined : toText(row.subject_id);
	};

	const attach = async (
		statement: string,
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): Promise<
		{ readonly subjectId: string; readonly inserted: boolean } | undefined
	> => {
		const [provider, externalId, email, emailVerified] = columnsOf(identity);
		const parameters = [
			tenant,
			provider,
			externalId,
			subjectId,
			email,
			emailVerified,
		];

		for (let attempt = 0; attempt < MAXIMUM_ATTEMPTS; attempt += 1) {
			const [inserted] = await run(statement, parameters).catch(
				(error: unknown) => {
					if (isForeignKeyViolation(error)) {
						return [];
					}

					throw error;
				},
			);

			if (inserted !== undefined) {
				return { subjectId, inserted: true };
			}

			const existing = await owner(tenant, provider, externalId);

			if (existing !== undefined) {
				return { subjectId: existing, inserted: false };
			}
		}

		return undefined;
	};

	const emailOf = (email: CanonicalEmail): string => email.address;

	return {
		findSubject: (tenant, provider, externalId) =>
			owner(tenant, provider, externalId),
		async findSubjectByVerifiedEmail(tenant, email) {
			const [row] = await run(VERIFIED_OWNER, [tenant, emailOf(email)]);

			return row === undefined ? undefined : toText(row.subject_id);
		},
		async createSubject(tenant, identity) {
			const attached = await attach(
				CREATE,
				tenant,
				crypto.randomUUID(),
				identity,
			);

			if (attached === undefined) {
				throw new Error("The identity kept appearing and disappearing");
			}

			return { subjectId: attached.subjectId, isNew: attached.inserted };
		},
		async linkIdentity(tenant, subjectId, identity) {
			return (await attach(LINK, tenant, subjectId, identity))?.subjectId;
		},
		async getSubject(tenant, subjectId) {
			const [row] = await run(SUBJECT, [tenant, subjectId]);

			if (row === undefined) {
				return undefined;
			}

			const evictedAt = row.evicted_at_milliseconds;

			return {
				evictedAtMilliseconds:
					evictedAt === null || evictedAt === undefined
						? undefined
						: toNumber(evictedAt),
			};
		},
		async findSubjectsByUnverifiedEmail(tenant, email) {
			const rows = await run(UNVERIFIED_CLAIMANTS, [tenant, emailOf(email)]);

			return rows.map((row) => toText(row.subject_id));
		},
		async removeUnverifiedEmailClaims(tenant, email, keepSubjectId) {
			const rows = await run(REMOVE_UNVERIFIED_CLAIMS, [
				tenant,
				emailOf(email),
				keepSubjectId,
			]);

			return rows.map((row) => toText(row.subject_id));
		},
		async deleteSubject(tenant, subjectId) {
			return (await run(DELETE_SUBJECT, [tenant, subjectId])).length > 0;
		},
	};
}
