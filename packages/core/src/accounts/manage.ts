import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import {
	REVOCATION_SCOPES,
	type SessionTokens,
} from "../session-tokens/session-tokens.js";
import { isStorableText } from "../shared/is-storable-text.js";
import type {
	AccountStore,
	MembershipStatus,
	StoredMembership,
} from "./account-store.js";
import { revokeAccount } from "./apply.js";
import type { Records } from "./records.js";

const MAXIMUM_TENANT_ID_LENGTH = 128;

/** A membership as the application sees it. */
export type Membership = {
	readonly tenant: string;
	readonly subject: string;
	readonly status: MembershipStatus;
};

/** Tenants, created by the application; a sign in reaches only one that exists and is enabled. */
export type Tenants = {
	create(id: string): Promise<Result<string>>;
	/** Signs nobody in to the tenant any more and revokes all of its sessions. */
	disable(id: string): Promise<Result<string>>;
	enable(id: string): Promise<Result<string>>;
};

/** Accounts, which only a sign in creates. */
export type Accounts = {
	/**
	 * Deletes the account with its identities and the data its factors keep,
	 * and revokes its sessions. Its subjects stay, with no account behind them,
	 * so the data of the application keeps its foreign keys; they are returned
	 * for the application to clean its own data.
	 */
	delete(account: string): Promise<Result<readonly Membership[]>>;
};

/** Memberships, which only a sign in creates; the application holds them back, removes and restores them. */
export type Memberships = {
	/** Keeps the subject out until it is restored, and revokes its sessions. */
	suspend(tenant: string, subject: string): Promise<Result<Membership>>;
	/** Lets a suspended or removed subject in again, with the same id. */
	restore(tenant: string, subject: string): Promise<Result<Membership>>;
	/** Takes the subject out of the tenant and revokes its sessions; it keeps its id, and a sign in the registration policy allows brings it back. */
	remove(tenant: string, subject: string): Promise<Result<Membership>>;
};

/** What the management parts need. */
export type ManagementOptions = {
	readonly store: AccountStore;
	readonly records: Records;
	readonly sessionTokens: Pick<SessionTokens, "revoke">;
	/** Called for every factor when an account is deleted, so it forgets what it keeps. */
	readonly forget: (account: string) => Promise<void>;
	readonly audit?: AuditSink | undefined;
};

const viewOf = (membership: StoredMembership): Membership =>
	Object.freeze({
		tenant: membership.tenant,
		subject: membership.subjectId,
		status: membership.status,
	});

/**
 * Creates the management parts. Each change that takes access away revokes
 * sessions first and changes the records after, so a failure half way never
 * leaves a live session of someone who is out; a change that gives access
 * back is recorded in the audit before it is made. A record whose seal does
 * not match is not changed: the operation refuses with `invalid-record`.
 */
export function createManagement(options: ManagementOptions): {
	readonly tenants: Tenants;
	readonly accounts: Accounts;
	readonly memberships: Memberships;
} {
	const { store, records, sessionTokens, forget } = options;
	const audit = options.audit;

	const record = (
		event: string,
		outcome: (typeof AUDIT_OUTCOMES)[keyof typeof AUDIT_OUTCOMES],
		reason: string,
		tenant: string,
		subject: string,
		detail: Readonly<Record<string, string>> = {},
	) => report(audit, { event, outcome, reason, tenant, subject, detail });

	const refuse = async (
		event: string,
		reason: string,
		code: string,
		tenant: string,
		subject: string,
		detail: Readonly<Record<string, string>> = {},
	) => {
		await record(
			event,
			AUDIT_OUTCOMES.refusal,
			reason,
			tenant,
			subject,
			detail,
		);

		return fail(code);
	};

	const setTenantDisabled = async (
		id: string,
		disabled: boolean,
	): Promise<Result<string>> => {
		const event = AUDIT_EVENTS.tenantChange;
		const reason = disabled ? AUDIT_REASONS.disabled : AUDIT_REASONS.enabled;

		if (!isStorableText(id)) {
			return refuse(
				event,
				AUDIT_REASONS.malformed,
				ERROR_CODES.invalidRequest,
				"",
				"",
			);
		}

		const current = await store.getTenant(id);

		if (current === undefined) {
			return refuse(
				event,
				AUDIT_REASONS.notFound,
				ERROR_CODES.noTenant,
				id,
				"",
			);
		}

		if ((await records.checkTenant(current)) === "invalid") {
			return refuse(
				event,
				AUDIT_REASONS.invalidRecord,
				ERROR_CODES.invalidRecord,
				id,
				"",
			);
		}

		if (disabled) {
			await sessionTokens.revoke({
				tenant: id,
				scope: REVOCATION_SCOPES.tenant,
			});
		} else {
			await record(event, AUDIT_OUTCOMES.success, reason, id, "");
		}

		const next = await records.tenant({ id, disabled });

		if (!(await store.setTenant(next, current.seal))) {
			return refuse(
				event,
				AUDIT_REASONS.conflict,
				ERROR_CODES.conflict,
				id,
				"",
			);
		}

		if (disabled) {
			await record(event, AUDIT_OUTCOMES.success, reason, id, "");
		}

		return succeed(id);
	};

	const changeMembership = async (
		tenant: string,
		subject: string,
		status: MembershipStatus,
	): Promise<Result<Membership>> => {
		const event = AUDIT_EVENTS.membershipChange;
		const reason =
			status === "active"
				? AUDIT_REASONS.restored
				: status === "suspended"
					? AUDIT_REASONS.suspended
					: AUDIT_REASONS.removed;

		if (!isStorableText(tenant) || !isStorableText(subject)) {
			return refuse(
				event,
				AUDIT_REASONS.malformed,
				ERROR_CODES.invalidRequest,
				"",
				"",
			);
		}

		const current = await store.getMembership(tenant, subject);

		if (current === undefined || current.accountId === undefined) {
			return refuse(
				event,
				AUDIT_REASONS.notFound,
				ERROR_CODES.noSubject,
				tenant,
				subject,
			);
		}

		if ((await records.checkMembership(current)) === "invalid") {
			return refuse(
				event,
				AUDIT_REASONS.invalidRecord,
				ERROR_CODES.invalidRecord,
				tenant,
				subject,
			);
		}

		const narrows = status !== "active";

		if (narrows) {
			await sessionTokens.revoke({
				tenant,
				scope: REVOCATION_SCOPES.user,
				id: subject,
			});
		} else {
			await record(event, AUDIT_OUTCOMES.success, reason, tenant, subject);
		}

		const next = await records.membership({
			subjectId: subject,
			tenant,
			accountId: current.accountId,
			status,
		});

		if (!(await store.setMembership(next, current.seal))) {
			return refuse(
				event,
				AUDIT_REASONS.conflict,
				ERROR_CODES.conflict,
				tenant,
				subject,
			);
		}

		if (narrows) {
			await record(event, AUDIT_OUTCOMES.success, reason, tenant, subject);
		}

		return succeed(viewOf(next));
	};

	return {
		tenants: {
			async create(id) {
				const event = AUDIT_EVENTS.tenantChange;

				if (!isStorableText(id) || id.length > MAXIMUM_TENANT_ID_LENGTH) {
					return refuse(
						event,
						AUDIT_REASONS.malformed,
						ERROR_CODES.invalidRequest,
						"",
						"",
					);
				}

				await record(
					event,
					AUDIT_OUTCOMES.success,
					AUDIT_REASONS.created,
					id,
					"",
				);

				const created = await store.createTenant(
					await records.tenant({ id, disabled: false }),
				);

				return created === "created"
					? succeed(id)
					: refuse(event, AUDIT_REASONS.conflict, ERROR_CODES.conflict, id, "");
			},
			disable: (id) => setTenantDisabled(id, true),
			enable: (id) => setTenantDisabled(id, false),
		},
		accounts: {
			async delete(account) {
				const event = AUDIT_EVENTS.accountDelete;

				if (!isStorableText(account)) {
					return refuse(
						event,
						AUDIT_REASONS.malformed,
						ERROR_CODES.invalidRequest,
						"",
						"",
					);
				}

				if ((await store.getAccount(account)) === undefined) {
					return refuse(
						event,
						AUDIT_REASONS.notFound,
						ERROR_CODES.noSubject,
						"",
						"",
						{ account },
					);
				}

				const before = await store.listMemberships(account);

				await revokeAccount({ store, sessionTokens }, account);
				await forget(account);

				const left = await store.deleteAccount(account);

				for (const membership of left ?? []) {
					if (
						!before.some(
							(earlier) => earlier.subjectId === membership.subjectId,
						)
					) {
						await sessionTokens.revoke({
							tenant: membership.tenant,
							scope: REVOCATION_SCOPES.user,
							id: membership.subjectId,
						});
					}
				}

				if (left === undefined) {
					return refuse(
						event,
						AUDIT_REASONS.notFound,
						ERROR_CODES.noSubject,
						"",
						"",
						{ account },
					);
				}

				await record(
					event,
					AUDIT_OUTCOMES.success,
					AUDIT_REASONS.deleted,
					"",
					"",
					{ account, subjects: String(left.length) },
				);

				return succeed(Object.freeze(left.map(viewOf)));
			},
		},
		memberships: {
			suspend: (tenant, subject) =>
				changeMembership(tenant, subject, "suspended"),
			restore: (tenant, subject) => changeMembership(tenant, subject, "active"),
			remove: (tenant, subject) => changeMembership(tenant, subject, "removed"),
		},
	};
}
