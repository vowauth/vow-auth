/** Names of the events the core reports. Applications may report their own events through the same sink. */
export const AUDIT_EVENTS = {
	authorizeCheck: "authorize.check",
	identityResolve: "identity.resolve",
	policyEvaluate: "policy.evaluate",
	proofVerify: "proof.verify",
	sessionIssue: "session.issue",
	sealUnseal: "seal.unseal",
	sessionRevoke: "session.revoke",
	sessionVerify: "session.verify",
	tokenConsume: "token.consume",
	tokenIssue: "token.issue",
} as const;

/** Whether an operation granted what was asked or refused it. */
export const AUDIT_OUTCOMES = {
	refusal: "refusal",
	success: "success",
} as const;

export type AuditOutcome = (typeof AUDIT_OUTCOMES)[keyof typeof AUDIT_OUTCOMES];

/**
 * Why an operation refused. Callers of the core only ever see one generic
 * error per operation; these reasons exist for the audit alone, so a refusal
 * can be investigated without telling an attacker anything.
 */
export const AUDIT_REASONS = {
	allowed: "allowed",
	authorizeError: "authorize-error",
	consumed: "consumed",
	expired: "expired",
	factorError: "factor-error",
	factorRejected: "factor-rejected",
	forbidden: "forbidden",
	invalidClaims: "invalid-claims",
	invalidEmail: "invalid-email",
	invalidSeal: "invalid-seal",
	issued: "issued",
	malformed: "malformed",
	malformedChain: "malformed-chain",
	noProof: "no-proof",
	notFound: "not-found",
	revoked: "revoked",
	undecryptable: "undecryptable",
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
