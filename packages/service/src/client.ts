import {
	type DelegateInput,
	type Delegation,
	ERROR_CODES,
	fail,
	type IdentityChange,
	type MeterObservation,
	type MeterRefusal,
	type MeterRule,
	type MeterScope,
	type MutationOutcome,
	RESOLUTION_OUTCOMES,
	type Result,
	type RevocationLevel,
	type SignedIn,
	type SignInRefusal,
	type SignInRequest,
	succeed,
	type VerifiedAgent,
	type VerifiedSession,
} from "@vow-auth/core";
import { SERVICE_ROUTES, type ServiceSurface } from "./protocol.js";
import { field, isFiniteNumber, isString } from "./shared.js";

/** Why a call to the service did not get a usable answer. */
export type UnavailableReason =
	| "network"
	| "timeout"
	| "unauthorized"
	| "server-error"
	| "malformed"
	| "unexpected-status";

/** Options for creating the client. */
export type AuthClientOptions = {
	readonly baseUrl: string;
	/** The secret the service expects as `Authorization: Bearer`. */
	readonly serviceToken: string;
	/** How long to wait for an answer; a call that takes longer is refused. */
	readonly timeoutMilliseconds: number;
	readonly fetch?: typeof fetch;
	/**
	 * Told why a call got no usable answer, for logs and metrics. It never
	 * changes the outcome, and an error it throws is ignored.
	 */
	readonly onUnavailable?: (reason: UnavailableReason) => void;
};

type Envelope =
	| { readonly kind: "answer"; readonly body: unknown }
	| { readonly kind: "unavailable"; readonly reason: UnavailableReason };

/** The error that a call without a result throws when the service cannot be reached. */
export const unavailableError = (reason: UnavailableReason): Error => {
	return Object.assign(
		new Error(`The auth service is unavailable: ${reason}`),
		{
			code: ERROR_CODES.unavailable,
		},
	);
};

/** Whether an error says that the auth service could not be reached. */
export const isUnavailableError = (error: unknown): boolean => {
	return (
		typeof error === "object" &&
		error !== null &&
		Reflect.get(error, "code") === ERROR_CODES.unavailable
	);
};

const isStringArray = (value: unknown): value is readonly string[] => {
	return Array.isArray(value) && value.every(isString);
};

const parseSignedIn = (value: unknown): SignedIn | undefined => {
	const token = field(value, "token");
	const tenant = field(value, "tenant");
	const subject = field(value, "subject");
	const device = field(value, "device");
	const session = field(value, "session");
	const identity = field(value, "identity");
	const email = field(value, "email");
	const evicted = field(value, "evicted");

	if (
		!isString(token) ||
		!isString(tenant) ||
		!isString(subject) ||
		!isString(device) ||
		!isString(session) ||
		!(
			identity === RESOLUTION_OUTCOMES.created ||
			identity === RESOLUTION_OUTCOMES.existing ||
			identity === RESOLUTION_OUTCOMES.linked
		) ||
		(email !== undefined && !isString(email)) ||
		!isStringArray(evicted)
	) {
		return undefined;
	}

	return { token, tenant, subject, device, session, identity, email, evicted };
};

const parseVerifiedSession = (value: unknown): VerifiedSession | undefined => {
	const tenant = field(value, "tenant");
	const subject = field(value, "subject");
	const device = field(value, "device");
	const session = field(value, "session");
	const methods = field(value, "methods");
	const authenticatedAtMilliseconds = field(
		value,
		"authenticatedAtMilliseconds",
	);
	const authenticationAgeMilliseconds = field(
		value,
		"authenticationAgeMilliseconds",
	);

	return isString(tenant) &&
		isString(subject) &&
		isString(device) &&
		isString(session) &&
		isStringArray(methods) &&
		methods.length > 0 &&
		isFiniteNumber(authenticatedAtMilliseconds) &&
		isFiniteNumber(authenticationAgeMilliseconds)
		? {
				tenant,
				subject,
				device,
				session,
				methods,
				authenticatedAtMilliseconds,
				authenticationAgeMilliseconds,
			}
		: undefined;
};

const parseDelegation = (value: unknown): Delegation | undefined => {
	const token = field(value, "token");
	const delegation = field(value, "delegation");

	return isString(token) && isString(delegation)
		? { token, delegation }
		: undefined;
};

const parseVerifiedAgent = (value: unknown): VerifiedAgent | undefined => {
	const tenant = field(value, "tenant");
	const subject = field(value, "subject");
	const agent = field(value, "agent");
	const delegation = field(value, "delegation");
	const boundTo = field(value, "boundTo");
	const device = field(boundTo, "device");
	const session = field(boundTo, "session");
	const delegatedAtMilliseconds = field(value, "delegatedAtMilliseconds");

	if (
		!isString(tenant) ||
		!isString(subject) ||
		!isString(agent) ||
		!isString(delegation) ||
		!isFiniteNumber(delegatedAtMilliseconds)
	) {
		return undefined;
	}

	if (boundTo === undefined) {
		return {
			tenant,
			subject,
			agent,
			delegation,
			boundTo: undefined,
			delegatedAtMilliseconds,
		};
	}

	return isString(device) && isString(session)
		? {
				tenant,
				subject,
				agent,
				delegation,
				boundTo: { device, session },
				delegatedAtMilliseconds,
			}
		: undefined;
};

const parseReading = (
	value: unknown,
):
	| { used: number; remaining: number; resetsAtMilliseconds: number }
	| undefined => {
	const used = field(value, "used");
	const remaining = field(value, "remaining");
	const resetsAtMilliseconds = field(value, "resetsAtMilliseconds");

	return isFiniteNumber(used) &&
		isFiniteNumber(remaining) &&
		isFiniteNumber(resetsAtMilliseconds)
		? { used, remaining, resetsAtMilliseconds }
		: undefined;
};

const parseObservation = (value: unknown): MeterObservation | undefined => {
	const reading = parseReading(value);
	const wouldRefuse = field(value, "wouldRefuse");

	return reading !== undefined && typeof wouldRefuse === "boolean"
		? { ...reading, wouldRefuse }
		: undefined;
};

const parseOutcome = (value: unknown): MutationOutcome | undefined => {
	const affectedSubjects = field(value, "affectedSubjects");

	return isStringArray(affectedSubjects) ? { affectedSubjects } : undefined;
};

/**
 * Creates the client of the service. It gives back the same shapes as the
 * `Auth` that runs in process, so code written against one works with the
 * other. It refuses where it cannot know: a network error, a timeout, a
 * rejected secret, a 5xx, a body that is not exactly the expected answer, any
 * unexpected status, gives a refusal with the code \`unavailable\`, never a
 * success. A success comes only from a well formed answer of status 200. Calls
 * that return no result (\`revoke\`, \`observe\`) throw an error that
 * \`isUnavailableError\` recognizes, because a silent failure to revoke would be
 * worse than an error. Redirects are refused so that the secret never goes to
 * another address, a positive answer is never cached, and nothing is retried:
 * \`meter.consume\` and \`mutateIdentity\` are not idempotent, and the
 * application knows better when to try again.
 */
export function createAuthClient(options: AuthClientOptions): ServiceSurface {
	const { baseUrl, serviceToken, timeoutMilliseconds, onUnavailable } = options;
	const fetchImplementation = options.fetch ?? fetch;

	if (!Number.isFinite(timeoutMilliseconds) || timeoutMilliseconds <= 0) {
		throw new RangeError(
			"timeoutMilliseconds must be a positive finite number",
		);
	}

	const note = (reason: UnavailableReason): void => {
		try {
			onUnavailable?.(reason);
		} catch {
			return;
		}
	};

	const call = async (route: string, body: unknown): Promise<Envelope> => {
		let response: Response;

		try {
			response = await fetchImplementation(new URL(route, baseUrl), {
				method: "POST",
				headers: {
					authorization: `Bearer ${serviceToken}`,
					"content-type": "application/json",
				},
				body: JSON.stringify(body),
				redirect: "error",
				cache: "no-store",
				signal: AbortSignal.timeout(timeoutMilliseconds),
			});
		} catch (error) {
			const timedOut =
				error instanceof Error &&
				(error.name === "TimeoutError" || error.name === "AbortError");

			return { kind: "unavailable", reason: timedOut ? "timeout" : "network" };
		}

		if (response.status === 401 || response.status === 403) {
			return { kind: "unavailable", reason: "unauthorized" };
		}

		if (response.status >= 500) {
			return { kind: "unavailable", reason: "server-error" };
		}

		if (response.status !== 200) {
			return { kind: "unavailable", reason: "unexpected-status" };
		}

		try {
			return { kind: "answer", body: JSON.parse(await response.text()) };
		} catch {
			return { kind: "unavailable", reason: "malformed" };
		}
	};

	const ask = async <Value, Failure>(
		route: string,
		body: unknown,
		parseValue: (value: unknown) => Value | undefined,
		parseFailure: (error: unknown) => Failure | undefined,
		unavailable: Failure,
	): Promise<Result<Value, Failure>> => {
		const envelope = await call(route, body);

		if (envelope.kind === "unavailable") {
			note(envelope.reason);

			return fail(unavailable);
		}

		const ok = field(envelope.body, "ok");

		if (ok === true) {
			const value = parseValue(field(envelope.body, "value"));

			if (value !== undefined) {
				return succeed(value);
			}
		}

		if (ok === false) {
			const failure = parseFailure(field(envelope.body, "error"));

			if (failure !== undefined) {
				return fail(failure);
			}
		}

		note("malformed");

		return fail(unavailable);
	};

	const parseCode = (error: unknown): string | undefined => {
		return isString(error) && error.length > 0 ? error : undefined;
	};

	const parseSignInRefusal = (error: unknown): SignInRefusal | undefined => {
		const code = parseCode(error);

		if (code !== undefined) {
			return code;
		}

		const factor = field(error, "factor");
		const continuation = field(error, "continuation");

		return field(error, "code") === ERROR_CODES.stepUpRequired &&
			isString(factor) &&
			isString(continuation)
			? { code: ERROR_CODES.stepUpRequired, factor, continuation }
			: undefined;
	};

	const parseRefusal = (error: unknown): MeterRefusal | undefined => {
		const code = field(error, "code");
		const resetsAtMilliseconds = field(error, "resetsAtMilliseconds");

		if (code === ERROR_CODES.invalidRequest) {
			return { code };
		}

		return code === ERROR_CODES.rateLimited &&
			isFiniteNumber(resetsAtMilliseconds)
			? { code, resetsAtMilliseconds }
			: undefined;
	};

	const callWithoutResult = async (
		route: string,
		body: unknown,
	): Promise<Envelope & { kind: "answer" }> => {
		const envelope = await call(route, body);

		if (envelope.kind === "unavailable") {
			note(envelope.reason);

			throw unavailableError(envelope.reason);
		}

		return envelope;
	};

	return {
		signIn: (request: SignInRequest) => {
			return ask(
				SERVICE_ROUTES.signIn,
				{
					tenant: request.tenant,
					device: request.device,
					factor: request.factor.id,
					response: request.response,
					continuation: request.continuation,
				},
				parseSignedIn,
				parseSignInRefusal,
				ERROR_CODES.unavailable,
			);
		},
		sessions: {
			verify: (token: string) => {
				return ask(
					SERVICE_ROUTES.verifySession,
					{ token },
					parseVerifiedSession,
					parseCode,
					ERROR_CODES.unavailable,
				);
			},
			revoke: async (level: RevocationLevel) => {
				const answer = await callWithoutResult(SERVICE_ROUTES.revokeSession, {
					level,
				});

				if (field(answer.body, "ok") !== true) {
					note("malformed");

					throw unavailableError("malformed");
				}
			},
		},
		agents: {
			delegate: (sessionToken: string, input: DelegateInput) => {
				return ask(
					SERVICE_ROUTES.delegateAgent,
					{
						sessionToken,
						agent: input.agent,
						timeToLiveMilliseconds: input.timeToLive.milliseconds,
						boundToSession: input.boundToSession,
					},
					parseDelegation,
					parseCode,
					ERROR_CODES.unavailable,
				);
			},
			verify: (token: string) => {
				return ask(
					SERVICE_ROUTES.verifyAgent,
					{ token },
					parseVerifiedAgent,
					parseCode,
					ERROR_CODES.unavailable,
				);
			},
		},
		meter: {
			consume: (scope: MeterScope, rule: MeterRule, cost?: number) => {
				return ask<
					{ used: number; remaining: number; resetsAtMilliseconds: number },
					MeterRefusal
				>(
					SERVICE_ROUTES.meterConsume,
					{ scope, rule, cost },
					parseReading,
					parseRefusal,
					{ code: ERROR_CODES.unavailable },
				);
			},
			observe: (scope: MeterScope, rule: MeterRule, cost?: number) => {
				return ask<MeterObservation, MeterRefusal>(
					SERVICE_ROUTES.meterObserve,
					{ scope, rule, cost },
					parseObservation,
					parseRefusal,
					{ code: ERROR_CODES.unavailable },
				);
			},
		},
		mutateIdentity: (
			tenant: string,
			subject: string,
			change: IdentityChange,
		) => {
			return change.type === "delete"
				? ask(
						SERVICE_ROUTES.deleteIdentity,
						{ tenant, subject },
						parseOutcome,
						parseCode,
						ERROR_CODES.unavailable,
					)
				: Promise.resolve(fail(ERROR_CODES.invalidRequest));
		},
	};
}
