import type { GrantStore, RevocationLevel, StoredGrant } from "@vow-auth/core";
import { describe, expect, test } from "vitest";

/** What an adapter gives the grant contract. */
export type GrantStoreContractOptions = {
	readonly create: () => GrantStore | Promise<GrantStore>;
};

const unique = (prefix: string): string => `${prefix}${crypto.randomUUID()}`;

const HOUR = 3_600_000;

const grantOf = (overrides: Partial<StoredGrant>): StoredGrant => ({
	id: unique("grant-"),
	kind: "session",
	tokenHash: undefined,
	accountId: unique("acc_"),
	tenant: undefined,
	subjectId: undefined,
	device: undefined,
	agent: undefined,
	parentId: undefined,
	sessionId: undefined,
	proofs: undefined,
	authenticatedAtMilliseconds: 0,
	expiresAtMilliseconds: Date.now() + HOUR,
	idleExpiresAtMilliseconds: undefined,
	revoked: false,
	seal: unique("seal-"),
	...overrides,
});

const sessionOf = (accountId: string, device: string): StoredGrant =>
	grantOf({
		kind: "session",
		tokenHash: unique("hash-"),
		accountId,
		device,
		proofs: "[]",
		idleExpiresAtMilliseconds: Date.now() + HOUR / 2,
	});

const entryOf = (
	session: StoredGrant,
	tenant: string,
	subjectId: string,
): StoredGrant =>
	grantOf({
		kind: "tenant",
		accountId: session.accountId,
		tenant,
		subjectId,
		device: session.device,
		parentId: session.id,
		sessionId: session.id,
	});

const agentOf = (
	accountId: string,
	tenant: string,
	subjectId: string,
	agent: string,
	boundTo?: StoredGrant,
	session?: StoredGrant,
): StoredGrant =>
	grantOf({
		kind: "agent",
		tokenHash: unique("hash-"),
		accountId,
		tenant,
		subjectId,
		agent,
		device: session?.device,
		parentId: boundTo?.id,
		sessionId: session?.id,
	});

/**
 * Defines the tests every `GrantStore` must pass: a session is found by the
 * hash of its token, or by its id, with its entry into the tenant asked for, the live entry
 * before a revoked one; an entry is unique for a session and a tenant while
 * it lives; an agent is found with the session it is bound to; the idle end
 * of a session never moves back nor past its end; each level of revocation
 * marks exactly its grants and everything bound to them; and forgetting an
 * account deletes its grants. Call it inside a test file once per adapter.
 */
export function grantStoreContract(
	name: string,
	options: GrantStoreContractOptions,
): void {
	/** Two accounts with sessions, entries and agents in two tenants. */
	const createTree = async () => {
		const store = await options.create();
		const tenant = unique("tenant-");
		const other = unique("tenant-");
		const account = unique("acc_");
		const stranger = unique("acc_");
		const subject = unique("sub_");
		const otherSubject = unique("sub_");
		const strangerSubject = unique("sub_");
		const laptop = unique("device-");
		const phone = unique("device-");
		const desktop = unique("device-");

		const onLaptop = sessionOf(account, laptop);
		const inTenant = entryOf(onLaptop, tenant, subject);
		const inOther = entryOf(onLaptop, other, otherSubject);
		const bound = agentOf(
			account,
			tenant,
			subject,
			"search",
			inTenant,
			onLaptop,
		);
		const free = agentOf(account, tenant, subject, "claude");
		const onPhone = sessionOf(account, phone);
		const phoneInTenant = entryOf(onPhone, tenant, subject);
		const strangerSession = sessionOf(stranger, desktop);
		const strangerEntry = entryOf(strangerSession, tenant, strangerSubject);

		await store.createSession(onLaptop, inTenant);
		expect(await store.createGrant(inOther)).toBe("created");
		expect(await store.createGrant(bound)).toBe("created");
		expect(await store.createGrant(free)).toBe("created");
		await store.createSession(onPhone, phoneInTenant);
		await store.createSession(strangerSession, strangerEntry);

		const all = {
			onLaptop,
			inTenant,
			inOther,
			bound,
			free,
			onPhone,
			phoneInTenant,
			strangerSession,
			strangerEntry,
		};

		const revokedNames = async (): Promise<string[]> => {
			const names: string[] = [];

			for (const [label, grant] of Object.entries(all)) {
				const revoked =
					grant.kind === "agent"
						? (await store.findAgent(grant.tokenHash ?? ""))?.agent.revoked
						: grant.kind === "session"
							? (await store.findSession(grant.tokenHash ?? "", undefined))
									?.session.revoked
							: (
									await store.findSession(
										(grant.sessionId === onLaptop.id
											? onLaptop
											: grant.sessionId === onPhone.id
												? onPhone
												: strangerSession
										).tokenHash ?? "",
										grant.tenant,
									)
								)?.entry?.revoked;

				if (revoked === true) {
					names.push(label);
				}
			}

			return names.sort();
		};

		return {
			store,
			tenant,
			other,
			account,
			subject,
			laptop,
			all,
			revokedNames,
		};
	};

	describe(`${name}: the grant store contract`, () => {
		test("a session is found by the hash of its token, with its entry into the tenant asked for and the store's time", async () => {
			const { store, tenant, other, all } = await createTree();
			const before = await store.now();
			const reading = await store.findSession(
				all.onLaptop.tokenHash ?? "",
				tenant,
			);

			expect(reading?.session).toEqual(all.onLaptop);
			expect(reading?.entry).toEqual(all.inTenant);
			expect(reading?.now).toBeGreaterThanOrEqual(before);
			expect(
				(await store.findSession(all.onLaptop.tokenHash ?? "", other))?.entry,
			).toEqual(all.inOther);
			expect(
				(await store.findSession(all.onLaptop.tokenHash ?? "", undefined))
					?.entry,
			).toBeUndefined();
			expect(
				(await store.findSession(all.onLaptop.tokenHash ?? "", unique("t-")))
					?.entry,
			).toBeUndefined();
			expect(await store.findSession(unique("hash-"), tenant)).toBeUndefined();
		});

		test("a session is read by its id as by its token, and an id of any other grant reads nothing", async () => {
			const { store, tenant, other, all } = await createTree();
			const byToken = await store.findSession(
				all.onLaptop.tokenHash ?? "",
				tenant,
			);
			const byId = await store.getSession(all.onLaptop.id, tenant);

			expect(byId?.session).toEqual(byToken?.session);
			expect(byId?.entry).toEqual(all.inTenant);
			expect(typeof byId?.now).toBe("number");
			expect((await store.getSession(all.onLaptop.id, other))?.entry).toEqual(
				all.inOther,
			);
			expect(
				(await store.getSession(all.onLaptop.id, undefined))?.entry,
			).toBeUndefined();

			for (const grant of [all.inTenant, all.bound, all.free]) {
				expect(await store.getSession(grant.id, tenant)).toBeUndefined();
			}

			expect(await store.getSession(unique("grant-"), tenant)).toBeUndefined();

			await store.revoke({ scope: "session", id: all.onLaptop.id });

			const revoked = await store.getSession(all.onLaptop.id, tenant);

			expect(revoked?.session.revoked).toBe(true);
			expect(revoked?.entry?.revoked).toBe(true);
		});

		test("an entry is unique for a session and a tenant while it lives, and the live one is found first", async () => {
			const { store, tenant, subject, all } = await createTree();

			expect(
				await store.createGrant(entryOf(all.onLaptop, tenant, subject)),
			).toBe("conflict");
			expect(
				await store.revoke({ scope: "subject", tenant, id: subject }),
			).toBe(4);

			const again = entryOf(all.onLaptop, tenant, subject);

			expect(await store.createGrant(again)).toBe("created");
			expect(
				(await store.findSession(all.onLaptop.tokenHash ?? "", tenant))?.entry,
			).toEqual(again);
		});

		test("a grant under a parent that does not exist is refused", async () => {
			const { store, tenant, subject, account } = await createTree();
			const orphan = agentOf(
				account,
				tenant,
				subject,
				"search",
				grantOf({ kind: "tenant" }),
			);

			expect(await store.createGrant(orphan)).toBe("conflict");
		});

		test("an agent is found with the session it is bound to, and alone when it is not", async () => {
			const { store, all } = await createTree();
			const bound = await store.findAgent(all.bound.tokenHash ?? "");
			const free = await store.findAgent(all.free.tokenHash ?? "");

			expect(bound?.agent).toEqual(all.bound);
			expect(bound?.session).toEqual(all.onLaptop);
			expect(free?.agent).toEqual(all.free);
			expect(free?.session).toBeUndefined();
			expect(typeof free?.now).toBe("number");
			expect(await store.findAgent(unique("hash-"))).toBeUndefined();
		});

		test("the idle end of a session moves forward, never back and never past the end", async () => {
			const { store, all } = await createTree();
			const hash = all.onLaptop.tokenHash ?? "";
			const idle = all.onLaptop.idleExpiresAtMilliseconds ?? 0;
			const idleOf = async () =>
				(await store.findSession(hash, undefined))?.session
					.idleExpiresAtMilliseconds;

			await store.extendSession(all.onLaptop.id, idle - 1_000);
			expect(await idleOf()).toBe(idle);
			await store.extendSession(all.onLaptop.id, idle + 1_000);
			expect(await idleOf()).toBe(idle + 1_000);
			await store.extendSession(all.onLaptop.id, idle + 10 * HOUR);
			expect(await idleOf()).toBe(all.onLaptop.expiresAtMilliseconds);
			await store.extendSession(unique("grant-"), idle);
		});

		const levels: readonly [
			string,
			(tree: Awaited<ReturnType<typeof createTree>>) => RevocationLevel,
			readonly string[],
		][] = [
			[
				"a session takes its entries and the agents bound to it",
				({ all }) => ({ scope: "session", id: all.onLaptop.id }),
				["bound", "inOther", "inTenant", "onLaptop"],
			],
			[
				"a device takes every session on it with what is bound to them",
				({ laptop }) => ({ scope: "device", id: laptop }),
				["bound", "inOther", "inTenant", "onLaptop"],
			],
			[
				"an account takes every session of it, and leaves the agents that live on their own",
				({ account }) => ({ scope: "account", id: account }),
				[
					"bound",
					"inOther",
					"inTenant",
					"onLaptop",
					"onPhone",
					"phoneInTenant",
				],
			],
			[
				"a subject takes its entries and agents in the tenant",
				({ tenant, subject }) => ({ scope: "subject", tenant, id: subject }),
				["bound", "free", "inTenant", "phoneInTenant"],
			],
			[
				"a tenant takes everything in the tenant",
				({ tenant }) => ({ scope: "tenant", tenant }),
				["bound", "free", "inTenant", "phoneInTenant", "strangerEntry"],
			],
			[
				"an agent takes its grants in the tenant",
				({ tenant }) => ({ scope: "agent", tenant, id: "claude" }),
				["free"],
			],
			[
				"a delegation takes that grant",
				({ all }) => ({ scope: "delegation", id: all.bound.id }),
				["bound"],
			],
		];

		for (const [what, levelOf, expected] of levels) {
			test(`revoking ${what}, and nothing else`, async () => {
				const tree = await createTree();

				expect(await tree.store.revoke(levelOf(tree))).toBe(expected.length);
				expect(await tree.revokedNames()).toEqual([...expected].sort());
				expect(await tree.store.revoke(levelOf(tree))).toBe(expected.length);
				expect(await tree.revokedNames()).toEqual([...expected].sort());
			});
		}

		test("forgetting an account deletes its grants and no one else's", async () => {
			const { store, account, all } = await createTree();

			await store.forget(account);

			expect(
				await store.findSession(all.onLaptop.tokenHash ?? "", undefined),
			).toBeUndefined();
			expect(await store.findAgent(all.free.tokenHash ?? "")).toBeUndefined();
			expect(
				(
					await store.findSession(
						all.strangerSession.tokenHash ?? "",
						undefined,
					)
				)?.session,
			).toEqual(all.strangerSession);
		});
	});
}
