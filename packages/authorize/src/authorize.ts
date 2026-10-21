import {
	type Ability,
	type DeclaredAction,
	ForbiddenError,
	type ResourceMap,
	type ResourceName,
	type ShapeOf,
} from "@vetojs/core";
import {
	AUDIT_EVENTS,
	AUDIT_OUTCOMES,
	AUDIT_REASONS,
	type AuditSink,
	ERROR_CODES,
	fail,
	type Result,
	report,
	succeed,
} from "@vow-auth/core";

/** What is being asked: an action on a resource, and the row when it touches one. */
export type AuthorizeRequest<
	AC extends ResourceMap,
	R extends ResourceName<AC>,
> = {
	readonly action: DeclaredAction<AC, R>;
	readonly resource: R;
	readonly row?: ShapeOf<AC, R>;
};

/** Who asks and where; the audit record names them. */
export type AuthorizeContext = {
	readonly tenant: string;
	readonly subject: string;
	readonly audit: AuditSink;
};

/**
 * Asks an ability whether an action may happen, deciding for real: without a
 * row it passes only when no row could change the answer. Anything that is not
 * a clear allow is a refusal, including an error thrown while checking (for
 * example a relation the rules read that was not loaded), so the check fails
 * closed. Every verdict is recorded in the audit before it is returned: if
 * the sink throws, there is no allow.
 */
export async function authorize<
	AC extends ResourceMap,
	R extends ResourceName<AC>,
>(
	ability: Ability<AC>,
	request: AuthorizeRequest<AC, R>,
	context: AuthorizeContext,
): Promise<Result<undefined>> {
	let reason: string = AUDIT_REASONS.allowed;

	try {
		ability.authorize(request.action, request.resource, request.row);
	} catch (error) {
		reason = ForbiddenError.is(error)
			? AUDIT_REASONS.forbidden
			: AUDIT_REASONS.authorizeError;
	}

	await report(context.audit, {
		event: AUDIT_EVENTS.authorizeCheck,
		outcome:
			reason === AUDIT_REASONS.allowed
				? AUDIT_OUTCOMES.success
				: AUDIT_OUTCOMES.refusal,
		reason,
		tenant: context.tenant,
		subject: context.subject,
		detail: {
			action: String(request.action),
			resource: String(request.resource),
		},
	});

	return reason === AUDIT_REASONS.allowed
		? succeed(undefined)
		: fail(ERROR_CODES.forbidden);
}
