import { readFile } from "node:fs/promises";
import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryOutboxStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	AUDIT_OUTCOMES,
	type AuditOutcome,
	type AuditSink,
	canonicalizeEmail,
	createAuth,
	createEmit,
	createOutboxWorker,
	defineDuration,
	defineMeterRule,
	type Factor,
	fail,
	type Result,
	type RevocationLevel,
	requireFactor,
	succeed,
} from "@vow-auth/core";
import { createEmailLink } from "@vow-auth/factor-email-link";

const PAGE_URL = new URL("../public/index.html", import.meta.url);
const MEMORY_BUDGET_BYTES = 10_000_000;
const LINK_TIME_TO_LIVE_MILLISECONDS = 10 * 60 * 1_000;
const SESSION_TIME_TO_LIVE_MILLISECONDS = 60 * 60 * 1_000;
const AUDIT_LIMIT = 300;
const LINK_REQUESTS_PER_WINDOW = 3;
const LINK_REQUEST_WINDOW_MILLISECONDS = 60 * 1_000;
const AUTHENTICATOR_ID = "authenticator";
const AUTHENTICATOR_CODE = "424242";
const STEP_UP_TIME_TO_LIVE_MILLISECONDS = 5 * 60 * 1_000;
const AGENT_TIME_TO_LIVE_MILLISECONDS = 30 * 60 * 1_000;

const definedLinkTimeToLive = defineDuration(LINK_TIME_TO_LIVE_MILLISECONDS);
const definedLinkRequestRule = defineMeterRule({
	limit: LINK_REQUESTS_PER_WINDOW,
	windowMilliseconds: LINK_REQUEST_WINDOW_MILLISECONDS,
});

const definedAgentTimeToLive = defineDuration(AGENT_TIME_TO_LIVE_MILLISECONDS);

if (
	!definedLinkTimeToLive.ok ||
	!definedLinkRequestRule.ok ||
	!definedAgentTimeToLive.ok
) {
	throw new Error("the limits of the playground must be valid");
}

const agentTimeToLive = definedAgentTimeToLive.value;

const linkTimeToLive = definedLinkTimeToLive.value;
const linkRequestRule = definedLinkRequestRule.value;
const SECRET_BYTES = 32;

type AuditEntry = {
	readonly id: string;
	readonly at: string;
	readonly event: string;
	readonly outcome: string;
	readonly reason: string;
	readonly tenant: string;
	readonly subject: string;
	readonly detail: string;
};

type Mail = {
	readonly id: string;
	readonly at: string;
	readonly to: string;
	readonly token: string;
};

type SubjectView = {
	readonly id: string;
	readonly tenant: string;
	readonly emails: readonly string[];
	readonly banned: boolean;
	readonly secondFactor: boolean;
};

type Delegated = {
	readonly delegation: string;
	readonly agent: string;
	readonly subject: string;
	readonly tenant: string;
	readonly boundToSession: boolean;
	readonly canWrite: boolean;
	readonly token: string;
};

/** The playground: the whole auth stack on in-memory adapters, behind a Fetch handler. */
export type Playground = {
	handle(request: Request): Promise<Response>;
	runWorker(): Promise<void>;
};

const field = (body: unknown, key: string): unknown => {
	return typeof body === "object" && body !== null && Object.hasOwn(body, key)
		? Reflect.get(body, key)
		: undefined;
};

const text = (body: unknown, key: string): string => {
	const value = field(body, key);

	return typeof value === "string" ? value.trim() : "";
};

const randomSecret = (): string => {
	return Array.from(
		crypto.getRandomValues(new Uint8Array(SECRET_BYTES)),
		(byte) => byte.toString(16).padStart(2, "0"),
	).join("");
};

const bearerToken = (request: Request): string => {
	const header = request.headers.get("authorization") ?? "";

	return header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
};

const respond = (status: number, body: unknown): Response => {
	return Response.json(body, { status });
};

const parseClaims = (raw: string): unknown => {
	try {
		return JSON.parse(raw);
	} catch {
		return undefined;
	}
};

const readJson = async (request: Request): Promise<unknown> => {
	try {
		return await request.json();
	} catch {
		return undefined;
	}
};

const describeDetail = (detail: Readonly<Record<string, string>>): string => {
	return Object.entries(detail)
		.map(([key, value]) => `${key}=${value}`)
		.join(", ");
};

/** Creates a playground with empty state. */
export async function createPlayground(): Promise<Playground> {
	const settings = { mailProviderDown: false };
	const auditLog: AuditEntry[] = [];
	const mails: Mail[] = [];
	const subjects = new Map<string, { tenant: string; emails: Set<string> }>();
	const bannedSubjects = new Set<string>();
	const secondFactorSubjects = new Set<string>();
	const delegations = new Map<string, Delegated>();
	const notes = new Map<string, string[]>();

	const outbox = createMemoryOutboxStore();
	const emit = createEmit(outbox);
	const audit: AuditSink = async (record) => {
		const recorded = await emit({
			type: "audit.entry",
			payload: {
				at: new Date(record.atMilliseconds).toISOString(),
				event: record.event,
				outcome: record.outcome,
				reason: record.reason,
				tenant: record.tenant,
				subject: record.subject,
				detail: describeDetail(record.detail),
			},
		});

		if (!recorded.ok) {
			throw new Error(`the audit record was refused: ${recorded.error}`);
		}
	};
	const record = (
		event: string,
		outcome: AuditOutcome,
		reason: string,
		tenant: string,
		subject: string,
		detail: Readonly<Record<string, string>>,
	): Promise<void> => {
		return audit({
			event,
			outcome,
			reason,
			tenant,
			subject,
			detail,
			atMilliseconds: Date.now(),
		});
	};

	const identities = createMemoryIdentityStore();
	const auth = createAuth({
		identities,
		epochs: createMemoryEpochStore({ maximumBytes: MEMORY_BUDGET_BYTES }),
		tokenStore: createMemoryTokenStore({ maximumBytes: MEMORY_BUDGET_BYTES }),
		meterStore: createMemoryMeterStore({ maximumBytes: MEMORY_BUDGET_BYTES }),
		secrets: [{ version: 1, value: randomSecret() }],
		maximumLifeTimeMilliseconds: SESSION_TIME_TO_LIVE_MILLISECONDS,
		sessionTimeToLiveMilliseconds: SESSION_TIME_TO_LIVE_MILLISECONDS,
		stepUpTimeToLiveMilliseconds: STEP_UP_TIME_TO_LIVE_MILLISECONDS,
		policy: ({ subject, proofs }) => {
			if (bannedSubjects.has(subject)) {
				return "deny";
			}

			return secondFactorSubjects.has(subject) &&
				!proofs.some((proof) => proof.factor === AUTHENTICATOR_ID)
				? requireFactor(AUTHENTICATOR_ID)
				: "allow";
		},
		audit,
	});
	const emailLink = createEmailLink({
		tokens: auth.tokens,
		deliver: async (message) => {
			await emit({
				type: "email.send",
				payload: { to: message.email, token: message.token },
			});
		},
		timeToLive: linkTimeToLive,
	});
	const simulatedProvider: Factor = {
		id: "simulated-provider",
		strength: "possession",
		verify: async (response) => succeed(response),
	};

	const authenticatorExternalId = (account: string): string | undefined => {
		const address = canonicalizeEmail(account);

		return address === undefined
			? undefined
			: `authenticator:${address.address}`;
	};
	const authenticator: Factor = {
		id: AUTHENTICATOR_ID,
		strength: "possession",
		verify: async (response) => {
			const externalId = authenticatorExternalId(text(response, "account"));

			return externalId !== undefined &&
				text(response, "code") === AUTHENTICATOR_CODE
				? succeed({
						provider: AUTHENTICATOR_ID,
						externalId,
						emailVerified: false,
					})
				: fail("invalid-proof");
		},
	};

	const worker = createOutboxWorker({
		store: outbox,
		handlers: {
			"audit.entry": async (event) => {
				auditLog.unshift({
					id: event.id,
					at: event.payload.at ?? "",
					event: event.payload.event ?? "",
					outcome: event.payload.outcome ?? "",
					reason: event.payload.reason ?? "",
					tenant: event.payload.tenant ?? "",
					subject: event.payload.subject ?? "",
					detail: event.payload.detail ?? "",
				});
				auditLog.length = Math.min(auditLog.length, AUDIT_LIMIT);
			},
			"email.send": async (event) => {
				if (settings.mailProviderDown) {
					throw new Error("the mail provider is down");
				}

				mails.unshift({
					id: event.id,
					at: new Date().toISOString(),
					to: event.payload.to ?? "",
					token: event.payload.token ?? "",
				});
			},
		},
		batchSize: 50,
		leaseMilliseconds: 5_000,
		retryDelayMilliseconds: 2_000,
		maximumAttempts: 5,
	});

	const runSignIn = auth.signIn;

	const statusOf = (error: string): number => {
		switch (error) {
			case "invalid-request":
				return 400;
			case "invalid-proof":
				return 401;
			case "no-allow":
			case "forbidden":
				return 403;
			default:
				return 422;
		}
	};

	const signIn = async (
		tenant: string,
		device: string,
		factor: Factor,
		response: unknown,
		continuation?: string,
	): Promise<Response> => {
		const result = await runSignIn({
			tenant,
			device,
			factor,
			response,
			...(continuation === undefined ? {} : { continuation }),
		});

		if (!result.ok) {
			return typeof result.error === "string"
				? respond(statusOf(result.error), { error: result.error })
				: respond(401, {
						error: result.error.code,
						factor: result.error.factor,
						continuation: result.error.continuation,
					});
		}

		const signedIn = result.value;
		const known = subjects.get(signedIn.subject) ?? {
			tenant,
			emails: new Set<string>(),
		};

		if (signedIn.email !== undefined) {
			known.emails.add(signedIn.email);
		}

		subjects.set(signedIn.subject, known);

		for (const evicted of signedIn.evicted) {
			subjects.delete(evicted);
		}

		return respond(200, {
			token: signedIn.token,
			tenant,
			subject: signedIn.subject,
			device,
			session: signedIn.session,
			identity: signedIn.identity,
		});
	};

	const subjectViews = (): readonly SubjectView[] => {
		return Array.from(subjects, ([id, subject]) => ({
			id,
			tenant: subject.tenant,
			emails: Array.from(subject.emails),
			banned: bannedSubjects.has(id),
			secondFactor: secondFactorSubjects.has(id),
		}));
	};

	const revocationLevel = (
		scope: string,
		verified: {
			tenant: string;
			subject: string;
			device: string;
			session: string;
		},
		id: string,
	): Result<RevocationLevel> => {
		switch (scope) {
			case "agent":
			case "delegation":
				return id === ""
					? fail("id-required")
					: succeed({ tenant: verified.tenant, scope, id });
			case "tenant":
				return succeed({ tenant: verified.tenant, scope: "tenant" });
			case "user":
				return succeed({
					tenant: verified.tenant,
					scope: "user",
					id: verified.subject,
				});
			case "device":
				return succeed({
					tenant: verified.tenant,
					scope: "device",
					id: verified.device,
				});
			case "session":
				return succeed({
					tenant: verified.tenant,
					scope: "session",
					id: verified.session,
				});
			default:
				return fail("unknown-scope");
		}
	};

	const route = async (request: Request, path: string): Promise<Response> => {
		if (request.method === "GET" && path === "/") {
			return new Response(await readFile(PAGE_URL), {
				headers: { "content-type": "text/html; charset=utf-8" },
			});
		}

		if (request.method === "GET" && path === "/api/state") {
			const agents = await Promise.all(
				Array.from(delegations.values(), async (delegated) => ({
					delegation: delegated.delegation,
					agent: delegated.agent,
					subject: delegated.subject,
					boundToSession: delegated.boundToSession,
					canWrite: delegated.canWrite,
					alive: (await auth.agents.verify(delegated.token)).ok,
				})),
			);

			return respond(200, {
				settings,
				audit: auditLog,
				mails,
				subjects: subjectViews(),
				agents,
				outbox: { pending: outbox.pending(), buried: outbox.buried().length },
			});
		}

		if (request.method !== "POST") {
			return respond(404, { error: "not-found" });
		}

		const body = await readJson(request);

		switch (path) {
			case "/api/challenge": {
				const tenant = text(body, "tenant");
				const email = text(body, "email");
				const address = canonicalizeEmail(email);
				const allowance =
					address === undefined
						? undefined
						: await auth.meter.consume(
								{
									tenant,
									actor: address.address,
									resource: "email-link.challenge",
								},
								linkRequestRule,
							);

				if (allowance !== undefined && !allowance.ok) {
					return allowance.error.code === "rate-limited"
						? respond(429, {
								error: allowance.error.code,
								retryAfterSeconds: Math.ceil(
									(allowance.error.resetsAtMilliseconds - Date.now()) / 1_000,
								),
							})
						: respond(503, { error: allowance.error.code });
				}

				const result = await emailLink.challenge(email);

				await record(
					"app.challenge",
					result.ok ? AUDIT_OUTCOMES.success : AUDIT_OUTCOMES.refusal,
					result.ok ? "sent" : result.error,
					tenant,
					"",
					{ email },
				);

				return respond(
					result.ok ? 200 : 422,
					result.ok ? { ok: true } : { error: result.error },
				);
			}
			case "/api/sign-in/email-link":
				return signIn(
					text(body, "tenant"),
					text(body, "device"),
					emailLink.factor,
					text(body, "token"),
				);
			case "/api/sign-in/provider":
				return signIn(
					text(body, "tenant"),
					text(body, "device"),
					simulatedProvider,
					parseClaims(text(body, "claims")),
				);
			case "/api/sign-in/second-factor":
				return signIn(
					text(body, "tenant"),
					text(body, "device"),
					authenticator,
					{ account: text(body, "account"), code: text(body, "code") },
					text(body, "continuation"),
				);
			case "/api/second-factor/enable": {
				const verified = await auth.sessions.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const enabled = field(body, "enabled") !== false;
				const known = subjects.get(verified.value.subject);
				const account =
					known === undefined ? undefined : Array.from(known.emails)[0];
				const externalId =
					account === undefined ? undefined : authenticatorExternalId(account);

				if (!enabled) {
					secondFactorSubjects.delete(verified.value.subject);
					await record(
						"app.second-factor",
						AUDIT_OUTCOMES.success,
						"disabled",
						verified.value.tenant,
						verified.value.subject,
						{},
					);

					return respond(200, { enabled: false });
				}

				if (account === undefined || externalId === undefined) {
					return respond(422, { error: "no-email" });
				}

				await identities.linkIdentity(
					verified.value.tenant,
					verified.value.subject,
					{
						provider: AUTHENTICATOR_ID,
						externalId,
						emailVerified: false,
					},
				);
				secondFactorSubjects.add(verified.value.subject);
				await record(
					"app.second-factor",
					AUDIT_OUTCOMES.success,
					"enabled",
					verified.value.tenant,
					verified.value.subject,
					{},
				);

				return respond(200, {
					enabled: true,
					account,
					code: AUTHENTICATOR_CODE,
				});
			}
			case "/api/sensitive": {
				const verified = await auth.sessions.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const maximumAgeSeconds = Number(field(body, "maxAgeSeconds"));
				const requiredMethod = text(body, "requireMethod");
				const ageSeconds = Math.floor(
					verified.value.authenticationAgeMilliseconds / 1_000,
				);

				if (
					requiredMethod !== "" &&
					!verified.value.methods.includes(requiredMethod)
				) {
					return respond(403, {
						error: "step-up-required",
						needs: requiredMethod,
						methods: verified.value.methods,
					});
				}

				if (
					Number.isFinite(maximumAgeSeconds) &&
					ageSeconds > maximumAgeSeconds
				) {
					return respond(401, {
						error: "recent-sign-in-required",
						ageSeconds,
						maxAgeSeconds: maximumAgeSeconds,
					});
				}

				return respond(200, {
					ok: true,
					methods: verified.value.methods,
					ageSeconds,
				});
			}
			case "/api/notes": {
				const verified = await auth.sessions.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const list = notes.get(verified.value.subject) ?? [];

				if (text(body, "action") === "write") {
					list.push(`person: ${text(body, "text")}`);
					notes.set(verified.value.subject, list);
				}

				return respond(200, { actingAs: "person", notes: list });
			}
			case "/api/agents/delegate": {
				const verified = await auth.sessions.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const agent = text(body, "agent");
				const boundToSession = field(body, "boundToSession") === true;
				const canWrite = field(body, "canWrite") === true;
				const delegated = await auth.agents.delegate(bearerToken(request), {
					agent,
					timeToLive: agentTimeToLive,
					boundToSession,
				});

				if (!delegated.ok) {
					return respond(422, { error: delegated.error });
				}

				delegations.set(delegated.value.delegation, {
					delegation: delegated.value.delegation,
					agent,
					subject: verified.value.subject,
					tenant: verified.value.tenant,
					boundToSession,
					canWrite,
					token: delegated.value.token,
				});

				return respond(200, {
					token: delegated.value.token,
					delegation: delegated.value.delegation,
					agent,
					boundToSession,
					canWrite,
					subject: verified.value.subject,
				});
			}
			case "/api/agents/act": {
				const verified = await auth.agents.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const rights = delegations.get(verified.value.delegation);
				const action = text(body, "action");

				if (action === "write" && rights?.canWrite !== true) {
					await record(
						"app.agent-act",
						AUDIT_OUTCOMES.refusal,
						"forbidden",
						verified.value.tenant,
						verified.value.subject,
						{ agent: verified.value.agent, action },
					);

					return respond(403, {
						error: "forbidden",
						why: "this delegation does not allow writing; the right lives in the application, not in the token",
					});
				}

				const list = notes.get(verified.value.subject) ?? [];

				if (action === "write") {
					list.push(`${verified.value.agent}: ${text(body, "text")}`);
					notes.set(verified.value.subject, list);
				}

				return respond(200, {
					actingAs: "agent",
					agent: verified.value.agent,
					forPerson: verified.value.subject,
					delegation: verified.value.delegation,
					boundTo: verified.value.boundTo ?? null,
					notes: list,
				});
			}
			case "/api/me": {
				const verified = await auth.sessions.verify(bearerToken(request));

				return verified.ok
					? respond(200, verified.value)
					: respond(401, { error: verified.error });
			}
			case "/api/revoke": {
				const verified = await auth.sessions.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const level = revocationLevel(
					text(body, "scope"),
					verified.value,
					text(body, "id"),
				);

				if (!level.ok) {
					return respond(400, { error: level.error });
				}

				await auth.sessions.revoke(level.value);

				return respond(200, { ok: true, revoked: level.value.scope });
			}
			case "/api/settings": {
				settings.mailProviderDown = field(body, "mailProviderDown") === true;
				await record(
					"app.settings",
					AUDIT_OUTCOMES.success,
					"changed",
					"",
					"",
					{ mailProviderDown: String(settings.mailProviderDown) },
				);

				return respond(200, settings);
			}
			case "/api/delete-subject": {
				const subject = text(body, "subject");
				const known = subjects.get(subject);

				if (known === undefined) {
					return respond(404, { error: "no-subject" });
				}

				const deleted = await auth.mutateIdentity(known.tenant, subject, {
					type: "delete",
				});

				subjects.delete(subject);

				return deleted.ok
					? respond(200, { ok: true })
					: respond(422, { error: deleted.error });
			}
			case "/api/ban": {
				const subject = text(body, "subject");
				const banned = field(body, "banned") === true;

				if (banned) {
					bannedSubjects.add(subject);
				} else {
					bannedSubjects.delete(subject);
				}

				await record(
					"app.ban",
					AUDIT_OUTCOMES.success,
					banned ? "banned" : "unbanned",
					"",
					subject,
					{},
				);

				return respond(200, { ok: true });
			}
			default:
				return respond(404, { error: "not-found" });
		}
	};

	return {
		async handle(request) {
			return route(request, new URL(request.url).pathname);
		},
		async runWorker() {
			await worker.runOnce();
		},
	};
}
