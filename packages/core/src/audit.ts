import type { ValueOf } from "./shared/value-of.js";

/** Names of the events the core reports. Applications may report their own events through the same sink. */
export const AUDIT_EVENTS = {
	accountDelete: "account.delete",
	accountEvict: "account.evict",
	delegationGrant: "delegation.grant",
	identityResolve: "identity.resolve",
	membershipChange: "membership.change",
	meterConsume: "meter.consume",
	policyEvaluate: "policy.evaluate",
	proofVerify: "proof.verify",
	sessionIssue: "session.issue",
	sealUnseal: "seal.unseal",
	sessionRevoke: "session.revoke",
	signInContinue: "signin.continue",
	signingKeyChange: "signing-key.change",
	signingKeyLoad: "signing-key.load",
	sessionVerify: "session.verify",
	tokenConsume: "token.consume",
	tenantChange: "tenant.change",
	tokenIssue: "token.issue",
} as const;

/**
 * Whether an operation granted what was asked, refused it, or only observed
 * that it would have refused.
 */
export const AUDIT_OUTCOMES = {
	refusal: "refusal",
	success: "success",
} as const;

export type AuditOutcome = ValueOf<typeof AUDIT_OUTCOMES>;

/**
 * Why an operation refused. Callers of the core only ever see one generic
 * error per operation; these reasons exist for the audit alone, so a refusal
 * can be investigated without telling an attacker anything.
 */
export const AUDIT_REASONS = {
	capacity: "capacity",
	conflict: "conflict",
	consumed: "consumed",
	created: "created",
	deleted: "deleted",
	disabled: "disabled",
	enabled: "enabled",
	evicted: "evicted",
	expired: "expired",
	factorError: "factor-error",
	factorRejected: "factor-rejected",
	foreignProvider: "foreign-provider",
	forbidden: "forbidden",
	invalidClaims: "invalid-claims",
	invalidEmail: "invalid-email",
	invalidRecord: "invalid-record",
	invalidSeal: "invalid-seal",
	issued: "issued",
	limitExceeded: "limit-exceeded",
	malformed: "malformed",
	malformedChain: "malformed-chain",
	noProof: "no-proof",
	notFound: "not-found",
	notOwner: "not-owner",
	removed: "removed",
	restored: "restored",
	revoked: "revoked",
	rotated: "rotated",
	stepUp: "step-up",
	suspended: "suspended",
	tooSoon: "too-soon",
	undecryptable: "undecryptable",
	unverified: "unverified",
	unknownVersion: "unknown-version",
	verified: "verified",
	wrongPurpose: "wrong-purpose",
} as const;

/**
 * One fact about a security decision. Secrets never appear in it: not tokens,
 * not their hashes, not sealed values. `tenant` and `subject` are empty when
 * the operation does not know them.
 */
export type AuditRecord = {
	readonly event: string;
	readonly outcome: AuditOutcome;
	readonly reason: string;
	readonly tenant: string;
	readonly subject: string;
	readonly detail: Readonly<Record<string, string>>;
	readonly atMilliseconds: number;
};

/**
 * Receives audit records. It is an observer: it cannot change a decision.
 * If it throws, the operation fails with that error. Operations that widen
 * access (allow, issue, link) record first and act only if the record was
 * written; operations that narrow access (refuse, revoke) refuse or act first
 * and then record. Whoever needs non-blocking telemetry catches errors inside
 * the sink.
 */
export type AuditSink = (record: AuditRecord) => Promise<void>;

export type AuditEntry = Omit<AuditRecord, "atMilliseconds">;

export const report = async (
	sink: AuditSink | undefined,
	entry: AuditEntry,
): Promise<void> => {
	if (sink === undefined) {
		return;
	}

	await sink({
		event: entry.event,
		outcome: entry.outcome,
		reason: entry.reason,
		tenant: entry.tenant,
		subject: entry.subject,
		detail: { ...entry.detail },
		atMilliseconds: Date.now(),
	});
};
