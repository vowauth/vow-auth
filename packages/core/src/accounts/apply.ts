import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import type { RevocationLevel } from "../grants/grant-store.js";
import { fail, type Result, succeed } from "../result.js";
import type { AccountStore } from "./account-store.js";
import type { SignInPlan } from "./plan.js";

/** What applying a plan needs. */
export type ApplyOptions = {
	readonly store: AccountStore;
	/** Revokes a level of grants; the change that asks records itself. */
	readonly revoke: (level: RevocationLevel) => Promise<void>;
	readonly trustedProviders: readonly string[];
	readonly audit?: AuditSink | undefined;
};

/**
 * Revokes every grant of an account: its sessions with everything under
 * them, and in every tenant it is a member of, its entries and agents.
 */
export const revokeAccount = async (
	options: Pick<ApplyOptions, "store" | "revoke">,
	accountId: string,
): Promise<void> => {
	await options.revoke({ scope: "account", id: accountId });

	for (const membership of await options.store.listMemberships(accountId)) {
		await options.revoke({
			scope: "subject",
			tenant: membership.tenant,
			id: membership.subjectId,
		});
	}
};

/**
 * Writes what an allowed sign in changes, and evicts the unverified claims
 * of the email it proved. The resolution is recorded before anything is
 * written, so a failing sink writes nothing. Creating the account, linking
 * the identity and creating or returning the membership are first-wins: a
 * sign in that lost a race to another one refuses with `conflict`, and the
 * next attempt sees what the other one wrote. Updating the provider's data
 * and sealing records again under the newest secret are compare-and-set; one
 * that lost a race is skipped, as the row is fresher already.
 *
 * An eviction narrows access, so the grants of the claimants are revoked
 * before their claims are removed, and the grants of any claimant that
 * appeared in between right after: a failure half way leaves grants revoked
 * and claims in place, never a live session of an evicted account.
 * It answers the accounts the eviction touched.
 */
export async function applyPlan(
	options: ApplyOptions,
	plan: SignInPlan,
): Promise<Result<readonly string[]>> {
	const { store, trustedProviders } = options;
	const audit = options.audit;
	const { writes } = plan;

	const record = (outcome: typeof AUDIT_OUTCOMES.success, reason: string) =>
		report(audit, {
			event: AUDIT_EVENTS.identityResolve,
			outcome,
			reason,
			tenant: plan.tenant,
			subject: plan.subjectId,
			detail: {
				provider: plan.provider,
				account: plan.accountId,
				membership: plan.membership,
			},
		});

	const conflict = async () => {
		await report(audit, {
			event: AUDIT_EVENTS.identityResolve,
			outcome: AUDIT_OUTCOMES.refusal,
			reason: AUDIT_REASONS.conflict,
			tenant: plan.tenant,
			subject: plan.subjectId,
			detail: { provider: plan.provider, account: plan.accountId },
		});

		return fail(ERROR_CODES.conflict);
	};

	await record(AUDIT_OUTCOMES.success, plan.identity);

	if (writes.account !== undefined && writes.identity !== undefined) {
		const created = await store.createAccount(
			writes.account,
			writes.identity,
			writes.membership,
		);

		if (created !== "created") {
			return conflict();
		}
	} else {
		if (writes.identity !== undefined) {
			const linked = await store.linkIdentity(writes.identity);

			if (linked !== "linked") {
				return conflict();
			}
		}

		if (writes.membership !== undefined) {
			const created = await store.createMembership(writes.membership);

			if (created !== "created") {
				return conflict();
			}
		}
	}

	if (writes.membershipUpdate !== undefined) {
		const updated = await store.setMembership(
			writes.membershipUpdate.next,
			writes.membershipUpdate.expectedSeal,
		);

		if (!updated) {
			return conflict();
		}
	}

	if (writes.identityUpdate !== undefined) {
		await store.updateIdentity(
			writes.identityUpdate.next,
			writes.identityUpdate.expectedSeal,
		);
	}

	if (writes.accountUpdate !== undefined) {
		await store.setAccount(
			writes.accountUpdate.next,
			writes.accountUpdate.expectedSeal,
		);
	}

	if (writes.tenantUpdate !== undefined) {
		await store.setTenant(
			writes.tenantUpdate.next,
			writes.tenantUpdate.expectedSeal,
		);
	}

	const email = plan.verifiedEmail;

	if (email === undefined) {
		return succeed([]);
	}

	const earlier = await store.findEmailClaimants(
		email,
		plan.accountId,
		trustedProviders,
	);

	for (const claimant of earlier) {
		await revokeAccount(options, claimant);
	}

	const evicted = await store.evictEmailClaims(
		email,
		plan.accountId,
		trustedProviders,
	);

	for (const claimant of evicted) {
		if (!earlier.includes(claimant)) {
			await revokeAccount(options, claimant);
		}
	}

	if (evicted.length > 0) {
		await report(audit, {
			event: AUDIT_EVENTS.accountEvict,
			outcome: AUDIT_OUTCOMES.success,
			reason: AUDIT_REASONS.evicted,
			tenant: plan.tenant,
			subject: plan.subjectId,
			detail: { account: plan.accountId, evicted: String(evicted.length) },
		});
	}

	return succeed(evicted);
}
