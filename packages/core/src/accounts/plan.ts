import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	report,
} from "../audit.js";
import { ERROR_CODES } from "../errors.js";
import { isMintedProof } from "../proof.js";
import { fail, type Result, succeed } from "../result.js";
import { generateId } from "../shared/secret.js";
import type { ValueOf } from "../shared/value-of.js";
import type {
	AccountStore,
	StoredAccount,
	StoredIdentity,
	StoredMembership,
	StoredTenant,
} from "./account-store.js";
import type { Records } from "./records.js";

/** How the identity of a sign in resolved. */
export const RESOLUTION_OUTCOMES = {
	created: "created",
	existing: "existing",
	linked: "linked",
} as const;

export type ResolutionOutcome = ValueOf<typeof RESOLUTION_OUTCOMES>;

/** How the membership of a sign in resolved. */
export const MEMBERSHIP_OUTCOMES = {
	created: "created",
	existing: "existing",
	rejoined: "rejoined",
} as const;

export type MembershipOutcome = ValueOf<typeof MEMBERSHIP_OUTCOMES>;

const ACCOUNT_ID_PREFIX = "acc_";
const SUBJECT_ID_PREFIX = "sub_";

type Update<Record> = {
	readonly next: Record;
	readonly expectedSeal: string;
};

/** What a sign in will write once it is allowed; nothing is written before. */
export type PlanWrites = {
	readonly account?: StoredAccount;
	readonly identity?: StoredIdentity;
	readonly identityUpdate?: Update<StoredIdentity>;
	readonly membership?: StoredMembership;
	readonly membershipUpdate?: Update<StoredMembership>;
	readonly accountUpdate?: Update<StoredAccount>;
	readonly tenantUpdate?: Update<StoredTenant>;
};

/**
 * Who a proof is and what letting them in would change, read from the store
 * and checked against the seals, with nothing written. The ids of a new
 * account and a new membership are chosen here, so the policies see them.
 */
export type SignInPlan = {
	readonly tenant: string;
	readonly accountId: string;
	readonly subjectId: string;
	readonly identity: ResolutionOutcome;
	readonly membership: MembershipOutcome;
	readonly provider: string;
	/** Another account owns the email of an identity this sign in creates. */
	readonly emailOwnedByAnotherAccount: boolean;
	/** The email this sign in proves, verified by a trusted provider; its unverified claims elsewhere are evicted. */
	readonly verifiedEmail: string | undefined;
	readonly writes: PlanWrites;
};

/** What a plan needs. */
export type PlanOptions = {
	readonly store: AccountStore;
	readonly records: Records;
	readonly trustedProviders: readonly string[];
	readonly audit?: AuditSink | undefined;
};

type Checked<Record> =
	| { readonly ok: true; readonly update?: Update<Record> }
	| { readonly ok: false };

/**
 * Plans the sign in of a proof into a tenant. Only a proof that
 * `verifyProof` minted is planned; anything else is refused with `no-proof`.
 *
 * 1. the tenant exists and is not disabled;
 * 2. an identity of the claims belongs to its account; failing that, a
 *    verified email from a trusted provider links to the account that owns
 *    the email, verified by a trusted provider; failing that, a new account;
 * 3. an active membership is used, a removed one returns, a suspended one
 *    refuses, and an account without one gets a new one.
 *
 * Every record read is checked against its seal: one that does not match
 * refuses the sign in with `invalid-record`, and is never taken for missing,
 * so a forged row cannot turn into a new account. A record sealed under an
 * older secret is sealed again when the sign in is allowed. A verified email
 * from a provider that is not trusted counts as unverified.
 */
export async function planSignIn(
	options: PlanOptions,
	tenant: string,
	proof: unknown,
): Promise<Result<SignInPlan>> {
	const { store, records, trustedProviders } = options;
	const audit = options.audit;

	if (!isMintedProof(proof)) {
		await report(audit, {
			event: AUDIT_EVENTS.identityResolve,
			outcome: AUDIT_OUTCOMES.refusal,
			reason: AUDIT_REASONS.noProof,
			tenant,
			subject: "",
			detail: {},
		});

		return fail(ERROR_CODES.noProof);
	}

	const { claims } = proof;

	const refuse = async (
		reason: string,
		code: string,
		detail: Readonly<Record<string, string>> = {},
	) => {
		await report(audit, {
			event: AUDIT_EVENTS.identityResolve,
			outcome: AUDIT_OUTCOMES.refusal,
			reason,
			tenant,
			subject: "",
			detail: { provider: claims.provider, ...detail },
		});

		return fail(code);
	};

	const checked = async <Record extends { readonly seal: string }>(
		record: Record,
		check: (record: Record) => Promise<string>,
		reseal: (record: Record) => Promise<Record>,
	): Promise<Checked<Record>> => {
		const verdict = await check(record);

		if (verdict === "invalid") {
			return { ok: false };
		}

		return verdict === "stale"
			? {
					ok: true,
					update: { next: await reseal(record), expectedSeal: record.seal },
				}
			: { ok: true };
	};

	const storedTenant = await store.getTenant(tenant);

	if (storedTenant === undefined) {
		return refuse(AUDIT_REASONS.notFound, ERROR_CODES.noTenant, {
			record: "tenant",
		});
	}

	const tenantCheck = await checked(
		storedTenant,
		records.checkTenant,
		records.tenant,
	);

	if (!tenantCheck.ok) {
		return refuse(AUDIT_REASONS.invalidRecord, ERROR_CODES.invalidRecord, {
			record: "tenant",
		});
	}

	if (storedTenant.disabled) {
		return refuse(AUDIT_REASONS.disabled, ERROR_CODES.noTenant, {
			record: "tenant",
		});
	}

	const trusted = trustedProviders.includes(claims.provider);
	const verifiedEmail =
		claims.emailVerified && trusted ? claims.email.address : undefined;

	const accountOf = async (
		accountId: string,
	): Promise<Result<Checked<StoredAccount>>> => {
		const account = await store.getAccount(accountId);

		if (account === undefined || account.evicted) {
			return fail(AUDIT_REASONS.notFound);
		}

		return succeed(
			await checked(account, records.checkAccount, records.account),
		);
	};

	let accountId: string;
	let identity: ResolutionOutcome;
	let writes: PlanWrites = {};
	let accountIsNew = false;
	let emailOwnedByAnotherAccount = false;

	const stored = await store.findIdentity(claims.provider, claims.externalId);

	if (stored !== undefined) {
		const verdict = await records.checkIdentity(stored);

		if (verdict === "invalid") {
			return refuse(AUDIT_REASONS.invalidRecord, ERROR_CODES.invalidRecord, {
				record: "identity",
			});
		}

		const account = await accountOf(stored.accountId);

		if (!account.ok || !account.value.ok) {
			return refuse(AUDIT_REASONS.invalidRecord, ERROR_CODES.invalidRecord, {
				record: "account",
			});
		}

		accountId = stored.accountId;
		identity = RESOLUTION_OUTCOMES.existing;

		const email = claims.email?.address;

		if (
			verdict === "stale" ||
			stored.email !== email ||
			stored.emailVerified !== claims.emailVerified
		) {
			writes = {
				...writes,
				identityUpdate: {
					next: await records.identity({
						provider: stored.provider,
						externalId: stored.externalId,
						accountId,
						email,
						emailVerified: claims.emailVerified,
					}),
					expectedSeal: stored.seal,
				},
			};
		}

		if (account.value.update !== undefined) {
			writes = { ...writes, accountUpdate: account.value.update };
		}
	} else {
		const owner =
			verifiedEmail === undefined
				? undefined
				: await store.findVerifiedOwner(verifiedEmail, trustedProviders);

		if (owner !== undefined) {
			if ((await records.checkIdentity(owner)) === "invalid") {
				return refuse(AUDIT_REASONS.invalidRecord, ERROR_CODES.invalidRecord, {
					record: "identity",
				});
			}

			const account = await accountOf(owner.accountId);

			if (!account.ok || !account.value.ok) {
				return refuse(AUDIT_REASONS.invalidRecord, ERROR_CODES.invalidRecord, {
					record: "account",
				});
			}

			accountId = owner.accountId;
			identity = RESOLUTION_OUTCOMES.linked;

			if (account.value.update !== undefined) {
				writes = { ...writes, accountUpdate: account.value.update };
			}
		} else {
			accountId = generateId(ACCOUNT_ID_PREFIX);
			identity = RESOLUTION_OUTCOMES.created;
			accountIsNew = true;
			writes = {
				...writes,
				account: await records.account({
					id: accountId,
					managedByTenant: undefined,
					evicted: false,
				}),
			};

			if (claims.email !== undefined && verifiedEmail === undefined) {
				emailOwnedByAnotherAccount =
					(await store.findVerifiedOwner(
						claims.email.address,
						trustedProviders,
					)) !== undefined;
			}
		}

		writes = {
			...writes,
			identity: await records.identity({
				provider: claims.provider,
				externalId: claims.externalId,
				accountId,
				email: claims.email?.address,
				emailVerified: claims.emailVerified,
			}),
		};
	}

	let subjectId: string;
	let membership: MembershipOutcome;
	const current = accountIsNew
		? undefined
		: await store.findMembership(tenant, accountId);

	if (current === undefined) {
		subjectId = generateId(SUBJECT_ID_PREFIX);
		membership = MEMBERSHIP_OUTCOMES.created;
		writes = {
			...writes,
			membership: await records.membership({
				subjectId,
				tenant,
				accountId,
				status: "active",
			}),
		};
	} else {
		const verdict = await records.checkMembership(current);

		if (verdict === "invalid" || current.accountId !== accountId) {
			return refuse(AUDIT_REASONS.invalidRecord, ERROR_CODES.invalidRecord, {
				record: "membership",
			});
		}

		if (current.status === "suspended") {
			return refuse(AUDIT_REASONS.suspended, ERROR_CODES.suspended, {
				account: accountId,
			});
		}

		subjectId = current.subjectId;
		membership =
			current.status === "removed"
				? MEMBERSHIP_OUTCOMES.rejoined
				: MEMBERSHIP_OUTCOMES.existing;

		if (membership === MEMBERSHIP_OUTCOMES.rejoined || verdict === "stale") {
			writes = {
				...writes,
				membershipUpdate: {
					next: await records.membership({
						subjectId,
						tenant,
						accountId,
						status: "active",
					}),
					expectedSeal: current.seal,
				},
			};
		}
	}

	if (tenantCheck.update !== undefined) {
		writes = { ...writes, tenantUpdate: tenantCheck.update };
	}

	return succeed(
		Object.freeze({
			tenant,
			accountId,
			subjectId,
			identity,
			membership,
			provider: claims.provider,
			emailOwnedByAnotherAccount,
			verifiedEmail,
			writes: Object.freeze(writes),
		}),
	);
}
