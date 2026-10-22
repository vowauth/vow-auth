import { durationOf, meterRuleOf } from "@vow-auth/test-support";
import { describe, expect, test } from "vitest";
import {
	claimsFactor,
	createService,
	type Mode,
	totpFactor,
	unverifiedClaims,
	verifiedClaims,
} from "./support.js";

const MODES: readonly Mode[] = ["in-process", "remote"];

describe.each(MODES)("A27: the invariants hold the same in %s mode", (mode) => {
	const signIn = (
		surface: ReturnType<typeof createService>["surface"],
		claims: unknown,
		tenant = "acme",
		device = "laptop",
	) =>
		surface.signIn({ tenant, device, factor: claimsFactor, response: claims });

	test("A1: a sign in that is allowed gives a session that verifies, and nothing else does", async () => {
		const { surface } = createService(mode);
		const signedIn = await signIn(surface, verifiedClaims("alice@example.com"));

		if (!signedIn.ok) {
			throw new Error("the sign in must pass");
		}

		expect(signedIn.value).toMatchObject({
			tenant: "acme",
			device: "laptop",
			identity: "created",
			email: "alice@example.com",
			evicted: [],
		});

		const verified = await surface.sessions.verify(signedIn.value.token);

		expect(verified).toMatchObject({
			ok: true,
			value: {
				tenant: "acme",
				subject: signedIn.value.subject,
				device: "laptop",
				session: signedIn.value.session,
				methods: ["claims"],
			},
		});
		expect(await surface.sessions.verify("1.garbage")).toEqual({
			ok: false,
			error: "invalid-session",
		});
	});

	test("refusals of a sign in carry the same codes", async () => {
		const { surface, banned } = createService(mode);

		expect(await signIn(surface, { provider: "p" })).toEqual({
			ok: false,
			error: "invalid-proof",
		});
		expect(await signIn(surface, verifiedClaims("a@example.com"), "")).toEqual({
			ok: false,
			error: "invalid-request",
		});

		const first = await signIn(surface, verifiedClaims("a@example.com"));

		if (first.ok) {
			banned.add(first.value.subject);
		}

		expect(await signIn(surface, verifiedClaims("a@example.com"))).toEqual({
			ok: false,
			error: "no-allow",
		});
	});

	test("A3: an unverified claim never links, a verified one does", async () => {
		const { surface } = createService(mode);
		const victim = await signIn(surface, verifiedClaims("victim@example.com"));
		const attacker = await signIn(
			surface,
			unverifiedClaims("evil", "e-1", "victim@example.com"),
		);
		const linked = await signIn(
			surface,
			verifiedClaims("victim@example.com", "google"),
		);

		expect(victim.ok && attacker.ok && linked.ok).toBe(true);
		expect(attacker.ok && attacker.value.identity).toBe("created");
		expect(linked.ok && linked.value.identity).toBe("linked");
		expect(
			victim.ok && linked.ok && linked.value.subject === victim.value.subject,
		).toBe(true);
		expect(
			victim.ok &&
				attacker.ok &&
				attacker.value.subject !== victim.value.subject,
		).toBe(true);
	});

	test("A7: a revocation kills the level it names and nothing else", async () => {
		const { surface } = createService(mode);
		const claims = verifiedClaims("alice@example.com");
		const laptop = await signIn(surface, claims, "acme", "laptop");
		const phone = await signIn(surface, claims, "acme", "phone");

		if (!laptop.ok || !phone.ok) {
			throw new Error("both sign ins must pass");
		}

		await surface.sessions.revoke({
			tenant: "acme",
			scope: "device",
			id: "laptop",
		});

		expect((await surface.sessions.verify(laptop.value.token)).ok).toBe(false);
		expect((await surface.sessions.verify(phone.value.token)).ok).toBe(true);

		await surface.sessions.revoke({
			tenant: "acme",
			scope: "user",
			id: phone.value.subject,
		});

		expect(await surface.sessions.verify(phone.value.token)).toEqual({
			ok: false,
			error: "invalid-session",
		});
	});

	test("A9: a verified email evicts an earlier claim and its session by itself", async () => {
		const { surface } = createService(mode);
		const squatter = await signIn(
			surface,
			unverifiedClaims("evil", "e-1", "victim@example.com"),
		);
		const victim = await signIn(surface, verifiedClaims("victim@example.com"));

		if (!squatter.ok || !victim.ok) {
			throw new Error("both sign ins must pass");
		}

		expect(victim.value.evicted).toEqual([squatter.value.subject]);
		expect((await surface.sessions.verify(squatter.value.token)).ok).toBe(
			false,
		);
		expect((await surface.sessions.verify(victim.value.token)).ok).toBe(true);
	});

	test("A10: deleting a subject ends its sessions, and never reaches another tenant", async () => {
		const { surface } = createService(mode);
		const alice = await signIn(surface, verifiedClaims("alice@example.com"));

		if (!alice.ok) {
			throw new Error("the sign in must pass");
		}

		expect(
			await surface.mutateIdentity("globex", alice.value.subject, {
				type: "delete",
			}),
		).toEqual({ ok: false, error: "no-subject" });
		expect((await surface.sessions.verify(alice.value.token)).ok).toBe(true);
		expect(
			await surface.mutateIdentity("acme", alice.value.subject, {
				type: "delete",
			}),
		).toEqual({
			ok: true,
			value: { affectedSubjects: [alice.value.subject] },
		});
		expect((await surface.sessions.verify(alice.value.token)).ok).toBe(false);
	});

	test("A32: the meter refuses over the limit with the same shape, and observing refuses nothing", async () => {
		const { surface } = createService(mode);
		const scope = { tenant: "acme", actor: "alice", resource: "email-link" };
		const rule = meterRuleOf({ limit: 2, windowMilliseconds: 60_000 });
		const results = [];

		for (let request = 0; request < 3; request += 1) {
			results.push(await surface.meter.consume(scope, rule));
		}

		expect(results.map((result) => result.ok)).toEqual([true, true, false]);

		const refusal = results[2];

		expect(!refusal?.ok && refusal?.error).toMatchObject({
			code: "rate-limited",
			resetsAtMilliseconds: expect.any(Number),
		});

		const observation = await surface.meter.observe(scope, rule);

		expect(observation).toMatchObject({
			ok: true,
			value: { wouldRefuse: true },
		});
		expect(
			(await surface.meter.consume({ ...scope, actor: "bob" }, rule)).ok,
		).toBe(true);
	});

	test("A2: a step-up is the same refusal in both modes and the continuation finishes the sign in", async () => {
		const { surface, identities, stepUpSubjects } = createService(mode);
		const claims = verifiedClaims("alice@example.com");
		const enrolling = await signIn(surface, claims, "acme", "enrolling");

		if (!enrolling.ok) {
			throw new Error("the first sign in must pass");
		}

		await identities.linkIdentity("acme", enrolling.value.subject, {
			provider: "totp",
			externalId: "alice-totp",
			emailVerified: false,
		});
		stepUpSubjects.add(enrolling.value.subject);

		const challenge = await signIn(surface, claims);

		expect(challenge).toEqual({
			ok: false,
			error: {
				code: "step-up-required",
				factor: "totp",
				continuation: expect.any(String),
			},
		});

		const continuation =
			!challenge.ok && typeof challenge.error !== "string"
				? challenge.error.continuation
				: "";
		const done = await surface.signIn({
			tenant: "acme",
			device: "laptop",
			factor: totpFactor,
			response: {
				provider: "totp",
				externalId: "alice-totp",
				emailVerified: false,
			},
			continuation,
		});

		expect(done.ok && done.value.subject).toBe(enrolling.value.subject);

		const verified = done.ok
			? await surface.sessions.verify(done.value.token)
			: undefined;

		expect(verified?.ok && verified.value.methods).toEqual(["claims", "totp"]);
		expect(
			await surface.signIn({
				tenant: "acme",
				device: "laptop",
				factor: totpFactor,
				response: {},
				continuation,
			}),
		).toEqual({ ok: false, error: "invalid-token" });
	});

	test("A8: an agent is delegated, verified and revoked the same way in both modes", async () => {
		const { surface } = createService(mode);
		const alice = await signIn(surface, verifiedClaims("alice@example.com"));

		if (!alice.ok) {
			throw new Error("the sign in must pass");
		}

		const delegated = await surface.agents.delegate(alice.value.token, {
			agent: "mcp-client-7",
			timeToLive: durationOf(60_000),
			boundToSession: true,
		});

		if (!delegated.ok) {
			throw new Error("the delegation must pass");
		}

		expect(await surface.agents.verify(delegated.value.token)).toMatchObject({
			ok: true,
			value: {
				tenant: "acme",
				subject: alice.value.subject,
				agent: "mcp-client-7",
				delegation: delegated.value.delegation,
				boundTo: { device: "laptop", session: alice.value.session },
			},
		});
		expect(await surface.sessions.verify(delegated.value.token)).toEqual({
			ok: false,
			error: "invalid-session",
		});

		await surface.sessions.revoke({
			tenant: "acme",
			scope: "session",
			id: alice.value.session,
		});

		expect(await surface.agents.verify(delegated.value.token)).toEqual({
			ok: false,
			error: "invalid-session",
		});
		expect(
			await surface.agents.delegate(alice.value.token, {
				agent: "mcp-client-7",
				timeToLive: durationOf(60_000),
			}),
		).toEqual({ ok: false, error: "invalid-session" });
	});

	test("a scripted conversation gives the same answers in both modes", async () => {
		const transcripts = await Promise.all(
			MODES.map(async (candidate) => {
				const { surface } = createService(candidate);
				const seen = new Map<string, string>();
				const normalize = (value: unknown): unknown => {
					if (typeof value === "string") {
						if (value.length > 16) {
							const known = seen.get(value) ?? `<id:${seen.size}>`;

							seen.set(value, known);

							return known;
						}

						return value;
					}

					if (Array.isArray(value)) {
						return value.map(normalize);
					}

					if (typeof value === "object" && value !== null) {
						return Object.fromEntries(
							Object.entries(value)
								.filter(
									([key]) =>
										key !== "resetsAtMilliseconds" &&
										key !== "authenticatedAtMilliseconds" &&
										key !== "authenticationAgeMilliseconds",
								)
								.map(([key, nested]) => [key, normalize(nested)]),
						);
					}

					return value;
				};
				const steps: unknown[] = [];
				const claims = verifiedClaims("alice@example.com");
				const first = await signIn(surface, claims, "acme", "laptop");

				steps.push(first);

				if (first.ok) {
					steps.push(await surface.sessions.verify(first.value.token));
					steps.push(await signIn(surface, claims, "acme", "phone"));
					await surface.sessions.revoke({
						tenant: "acme",
						scope: "device",
						id: "laptop",
					});
					steps.push(await surface.sessions.verify(first.value.token));
					steps.push(
						await surface.mutateIdentity("acme", first.value.subject, {
							type: "delete",
						}),
					);
					steps.push(await signIn(surface, claims, "acme", "tablet"));
				}

				steps.push(await signIn(surface, { provider: "p" }));
				steps.push(
					await surface.meter.consume(
						{ tenant: "acme", actor: "a", resource: "r" },
						meterRuleOf({ limit: 1, windowMilliseconds: 60_000 }),
					),
				);

				return normalize(steps);
			}),
		);

		expect(transcripts[1]).toEqual(transcripts[0]);
	});
});
