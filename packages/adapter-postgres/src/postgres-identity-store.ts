import type {
	CanonicalEmail,
	IdentityClaims,
	IdentityStore,
} from "@vow-auth/core";
import { type PostgresRunner, toText } from "./postgres-runner.js";

const MAXIMUM_ATTEMPTS = 3;

type Columns = readonly [string, string, string | null, boolean];

const columnsOf = (identity: IdentityClaims): Columns => [
	identity.provider,
	identity.externalId,
	identity.email?.address ?? null,
	identity.emailVerified,
];

const INSERT = `insert into vow_auth_identities
	(tenant, provider, external_id, subject_id, email, email_verified)
	values ($1, $2, $3, $4, $5, $6)
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
	returning subject_id
)
select subject_id from claimants`;

const DELETE_SUBJECT = `delete from vow_auth_identities
	where tenant = $1 and subject_id = $2
	returning seq`;

/**
 * Identity store on Postgres. A subject is the \`subject_id\` of its rows, so
 * it exists while it has an identity and cannot be left behind empty. The
 * primary key \`(tenant, provider, external_id)\` makes \`createSubject\` and
 * \`linkIdentity\` atomic and first-wins: a conflict leaves the existing row
 * and the call answers its owner. The owner of a verified email is the oldest
 * identity that verified it, so deleting the owner hands the email to the next
 * one. Removing the unverified claims of an email is one statement, so it
 * cannot stop half way. Every method names the tenant in its query.
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
		tenant: string,
		subjectId: string,
		identity: IdentityClaims,
	): Promise<{ readonly subjectId: string; readonly inserted: boolean }> => {
		const [provider, externalId, email, emailVerified] = columnsOf(identity);

		for (let attempt = 0; attempt < MAXIMUM_ATTEMPTS; attempt += 1) {
			const [inserted] = await run(INSERT, [
				tenant,
				provider,
				externalId,
				subjectId,
				email,
				emailVerified,
			]);

			if (inserted !== undefined) {
				return { subjectId, inserted: true };
			}

			const existing = await owner(tenant, provider, externalId);

			if (existing !== undefined) {
				return { subjectId: existing, inserted: false };
			}
		}

		throw new Error("The identity kept appearing and disappearing");
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
			const attached = await attach(tenant, crypto.randomUUID(), identity);

			return { subjectId: attached.subjectId, isNew: attached.inserted };
		},
		async linkIdentity(tenant, subjectId, identity) {
			return (await attach(tenant, subjectId, identity)).subjectId;
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
