import { readFile } from "node:fs/promises";
import {
	createMemoryEpochStore,
	createMemoryIdentityStore,
	createMemoryOutboxStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import {
	AUDIT_OUTCOMES,
	type AuditOutcome,
	type AuditSink,
	createEmit,
	createMutateIdentity,
	createOutboxWorker,
	createSealer,
	createSessionTokens,
	createTokens,
	evaluatePolicy,
	type Factor,
	fail,
	issueSession,
	type Result,
	type RevocationLevel,
	resolveIdentity,
	succeed,
	verifyProof,
} from "@vow-auth/core";
import { createEmailLink } from "@vow-auth/factor-email-link";

const PAGE_URL = new URL("../public/index.html", import.meta.url);
const MEMORY_BUDGET_BYTES = 10_000_000;
const LINK_TIME_TO_LIVE_MILLISECONDS = 10 * 60 * 1_000;
const SESSION_TIME_TO_LIVE_MILLISECONDS = 60 * 60 * 1_000;
const AUDIT_LIMIT = 300;
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
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: MEMORY_BUDGET_BYTES }),
		audit,
	});
	const sessionTokens = createSessionTokens({
		sealer: createSealer({
			secrets: [{ version: 1, value: randomSecret() }],
			audit,
		}),
		epochs: createMemoryEpochStore({ maximumBytes: MEMORY_BUDGET_BYTES }),
		maximumLifeTimeMilliseconds: SESSION_TIME_TO_LIVE_MILLISECONDS,
		audit,
	});
	const mutateIdentity = createMutateIdentity({
		store: identities,
		sessionTokens,
		audit,
	});
	const emailLink = createEmailLink({
		tokens,
		deliver: async (message) => {
			await emit({
				type: "email.send",
				payload: { to: message.email, token: message.token },
			});
		},
		timeToLiveMilliseconds: LINK_TIME_TO_LIVE_MILLISECONDS,
	});
	const simulatedProvider: Factor = {
		id: "simulated-provider",
		strength: "possession",
		verify: async (response) => succeed(response),
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

	const signIn = async (
		tenant: string,
		device: string,
		factor: Factor,
		response: unknown,
	): Promise<Response> => {
		if (tenant === "" || device === "") {
			return respond(400, { error: "tenant and device are required" });
		}

		const proof = await verifyProof(factor, response, { audit });

		if (!proof.ok) {
			return respond(401, { error: proof.error });
		}

		const resolution = await resolveIdentity(identities, tenant, proof.value, {
			audit,
		});

		if (!resolution.ok) {
			return respond(422, { error: resolution.error });
		}

		const { subjectId, outcome } = resolution.value;
		const known = subjects.get(subjectId) ?? {
			tenant,
			emails: new Set<string>(),
		};

		if (proof.value.claims.email !== undefined) {
			known.emails.add(proof.value.claims.email.address);
		}

		subjects.set(subjectId, known);

		if (proof.value.claims.emailVerified) {
			const confirmed = await mutateIdentity(tenant, subjectId, {
				type: "confirm-email",
				proof: proof.value,
			});

			for (const evicted of confirmed.ok
				? confirmed.value.affectedSubjects
				: []) {
				subjects.delete(evicted);
			}
		}

		const decision = await evaluatePolicy(
			subjectId,
			(id) => (bannedSubjects.has(id) ? "deny" : "allow"),
			{ audit, tenant },
		);
		const session = issueSession(decision);

		if (!session.ok) {
			return respond(403, { error: session.error });
		}

		const token = await sessionTokens.issue(session.value, {
			tenant,
			device,
			timeToLiveMilliseconds: SESSION_TIME_TO_LIVE_MILLISECONDS,
		});

		if (!token.ok) {
			return respond(500, { error: token.error });
		}

		return respond(200, {
			token: token.value,
			tenant,
			subject: subjectId,
			device,
			session: session.value.id,
			identity: outcome,
		});
	};

	const subjectViews = (): readonly SubjectView[] => {
		return Array.from(subjects, ([id, subject]) => ({
			id,
			tenant: subject.tenant,
			emails: Array.from(subject.emails),
			banned: bannedSubjects.has(id),
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
	): Result<RevocationLevel> => {
		switch (scope) {
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
			return respond(200, {
				settings,
				audit: auditLog,
				mails,
				subjects: subjectViews(),
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
			case "/api/me": {
				const verified = await sessionTokens.verify(bearerToken(request));

				return verified.ok
					? respond(200, verified.value)
					: respond(401, { error: verified.error });
			}
			case "/api/revoke": {
				const verified = await sessionTokens.verify(bearerToken(request));

				if (!verified.ok) {
					return respond(401, { error: verified.error });
				}

				const level = revocationLevel(text(body, "scope"), verified.value);

				if (!level.ok) {
					return respond(400, { error: level.error });
				}

				await sessionTokens.revoke(level.value);

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

				const deleted = await mutateIdentity(known.tenant, subject, {
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
