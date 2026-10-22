import { readFile } from "node:fs/promises";
import {
	type Ability,
	buildAbility,
	createRules,
	defineAbilities,
	shape,
} from "@vetojs/core";
import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryMeterStore,
	createMemoryOutboxStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { authorize, narrow } from "@vow-auth/authorize";
import {
	AUDIT_OUTCOMES,
	type AuditOutcome,
	type AuditSink,
	canonicalizeEmail,
	createAuth,
	createEmit,
	createOutboundGuard,
	createOutboxWorker,
	createRedirectPolicy,
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

const abilities = defineAbilities({
	resources: {
		note: { schema: shape<{ authorId: string }>(), actions: ["read", "write"] },
	},
});
const { allow, deny } = createRules(abilities);
const personAbility = buildAbility(abilities, [
	allow("read", "note"),
	allow("write", "note"),
]);

type NoteAbility = Ability<typeof abilities>;

const redirectPolicy = createRedirectPolicy({
	allowedOrigins: ["http://localhost:3000", "https://app.example.com"],
});
const SIMULATED_DNS: Readonly<Record<string, readonly string[]>> = {
	"hooks.example.com": ["93.184.216.34"],
	"rebind.example.com": ["10.0.0.5"],
};
const outboundGuard = createOutboundGuard({
	allowedHosts: Object.keys(SIMULATED_DNS),
	resolveAddresses: async (host) => SIMULATED_DNS[host] ?? [],
	fetch: async (input, init) =>
		Response.json({ called: String(input), redirect: init?.redirect }),
});

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
	readonly ability: NoteAbility;
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
	const settings: {
		mailProviderDown: boolean;
		rateLimitMode: "enforce" | "observe";
	} = { mailProviderDown: false, rateLimitMode: "enforce" };
	const auditLog: AuditEntry[] = [];
	const mails: Mail[] = [];
	const subjects = new Map<string, { tenant: string; emails: Set<string> }>();
	const bannedSubjects = new Set<string>();
	const secondFactorSubjects = new Set<string>();
	const delegations = new Map<string, Delegated>();
	const deadDelegations = new Set<string>();
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

	const isAlive = async (delegated: Delegated): Promise<boolean> => {
		if (deadDelegations.has(delegated.delegation)) {
			return false;
		}

		const verified = await auth.agents.verify(delegated.token);

		if (!verified.ok) {
			deadDelegations.add(delegated.delegation);
		}

		return verified.ok;
	};

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
					alive: await isAlive(delegated),
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
				const scope =
					address === undefined
						? undefined
						: {
								tenant,
								actor: address.address,
								resource: "email-link.challenge",
							};
				const observing = settings.rateLimitMode === "observe";
				const observation =
					scope !== undefined && observing
						? await auth.meter.observe(scope, linkRequestRule)
						: undefined;
				const allowance =
					scope === undefined || observing
						? undefined
						: await auth.meter.consume(scope, linkRequestRule);

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
					result.ok
						? {
								ok: true,
								...(observation?.ok
									? {
											observed: {
												wouldRefuse: observation.value.wouldRefuse,
												used: observation.value.used,
												remaining: observation.value.remaining,
											},
										}
									: {}),
							}
						: { error: result.error },
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

				const personAction =
					text(body, "action") === "write" ? "write" : "read";
				const personAllowed = await authorize(
					personAbility,
					{ action: personAction, resource: "note" },
					{
						tenant: verified.value.tenant,
						subject: verified.value.subject,
						audit,
					},
				);

				if (!personAllowed.ok) {
					return respond(403, { error: "forbidden" });
				}

				const list = notes.get(verified.value.subject) ?? [];

				if (personAction === "write") {
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
				const narrowed = narrow(
					abilities,
					personAbility,
					canWrite ? [] : [deny("write", "note")],
				);
				const delegated = await auth.agents.delegate(bearerToken(request), {
					agent,
					timeToLive: agentTimeToLive,
					boundToSession,
				});

				if (!delegated.ok || !narrowed.ok) {
					return respond(422, {
						error: delegated.ok ? "invalid-delegation" : delegated.error,
					});
				}

				delegations.set(delegated.value.delegation, {
					delegation: delegated.value.delegation,
					agent,
					subject: verified.value.subject,
					tenant: verified.value.tenant,
					boundToSession,
					canWrite,
					token: delegated.value.token,
					ability: narrowed.value,
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
				const action = text(body, "action") === "write" ? "write" : "read";
				const allowed = await authorize(
					rights?.ability ?? buildAbility(abilities, []),
					{ action, resource: "note" },
					{
						tenant: verified.value.tenant,
						subject: verified.value.subject,
						audit,
					},
				);

				if (!allowed.ok) {
					return respond(403, {
						error: "forbidden",
						why: "the delegation's ability, built with narrow from the person's own, does not allow this; the right lives in the application, not in the token",
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
				if (field(body, "mailProviderDown") !== undefined) {
					settings.mailProviderDown = field(body, "mailProviderDown") === true;
				}

				if (field(body, "rateLimitMode") !== undefined) {
					settings.rateLimitMode =
						field(body, "rateLimitMode") === "observe" ? "observe" : "enforce";
				}

				await record(
					"app.settings",
					AUDIT_OUTCOMES.success,
					"changed",
					"",
					"",
					{
						mailProviderDown: String(settings.mailProviderDown),
						rateLimitMode: settings.rateLimitMode,
					},
				);

				return respond(200, settings);
			}
			case "/api/probe/meter": {
				const limit = Number(field(body, "limit") ?? LINK_REQUESTS_PER_WINDOW);
				const windowMilliseconds = Number(
					field(body, "windowMilliseconds") ?? LINK_REQUEST_WINDOW_MILLISECONDS,
				);
				const cost = field(body, "cost");
				const rule = defineMeterRule({ limit, windowMilliseconds });

				if (!rule.ok) {
					return respond(200, { defined: false, error: rule.error });
				}

				const consumed = await auth.meter.consume(
					{ tenant: "probe", actor: "probe", resource: "probe" },
					rule.value,
					typeof cost === "number" ? cost : undefined,
				);

				return respond(
					200,
					consumed.ok
						? { defined: true, ok: true, ...consumed.value }
						: { defined: true, ok: false, error: consumed.error },
				);
			}
			case "/api/probe/redirect": {
				const checked = redirectPolicy(field(body, "target"));

				return respond(
					200,
					checked.ok
						? { ok: true, to: checked.value }
						: { ok: false, error: checked.error },
				);
			}
			case "/api/probe/outbound": {
				const called = await outboundGuard.fetch(field(body, "url"));

				return respond(
					200,
					called.ok
						? { ok: true, ...(await called.value.json()) }
						: { ok: false, error: called.error },
				);
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
