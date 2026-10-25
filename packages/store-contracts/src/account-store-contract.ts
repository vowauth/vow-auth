import type {
	AccountStore,
	StoredAccount,
	StoredIdentity,
	StoredMembership,
	StoredTenant,
} from "@vow-auth/core";
import { describe, expect, test } from "vitest";

/** What an adapter gives the account contract. */
export type AccountStoreContractOptions = {
	readonly create: () => AccountStore | Promise<AccountStore>;
};

const unique = (prefix: string): string => `${prefix}${crypto.randomUUID()}`;

const tenantOf = (id = unique("tenant-")): StoredTenant => ({
	id,
	disabled: false,
	seal: unique("seal-"),
});

const accountOf = (id = unique("acc_")): StoredAccount => ({
	id,
	managedByTenant: undefined,
	evicted: false,
	seal: unique("seal-"),
});

const identityOf = (
	accountId: string,
	overrides: Partial<StoredIdentity> = {},
): StoredIdentity => ({
	provider: "email",
	externalId: unique("person-"),
	accountId,
	email: undefined,
	emailVerified: false,
	seal: unique("seal-"),
	...overrides,
});

const membershipOf = (
	tenant: string,
	accountId: string,
	overrides: Partial<StoredMembership> = {},
): StoredMembership => ({
	subjectId: unique("sub_"),
	tenant,
	accountId,
	status: "active",
	seal: unique("seal-"),
	...overrides,
});

const uniqueEmail = (): string => `${crypto.randomUUID()}@example.com`;

/**
 * Defines the tests every `AccountStore` must pass: an identity is unique in
 * the deployment and its first writer wins, a membership is unique for a
 * tenant and an account, creating an account leaves nothing behind on a
 * conflict, compare-and-set changes only the row the caller read, an
 * eviction removes exactly the claims that no trusted provider verified and
 * marks the emptied accounts, and deleting an account leaves its subjects
 * without one. Call it inside a test file once per adapter.
 */
export function accountStoreContract(
	name: string,
	options: AccountStoreContractOptions,
): void {
	const setUp = async () => {
		const store = await options.create();
		const tenant = tenantOf();

		expect(await store.createTenant(tenant)).toBe("created");

		const create = async (
			identity: Partial<StoredIdentity> = {},
			inTenant: string | null = tenant.id,
		) => {
			const account = accountOf();
			const first = identityOf(account.id, identity);
			const membership =
				inTenant === null ? undefined : membershipOf(inTenant, account.id);

			expect(await store.createAccount(account, first, membership)).toBe(
				"created",
			);

			return { account, identity: first, membership };
		};

		return { store, tenant, create };
	};

	describe(`${name}: the account store contract`, () => {
		test("a tenant is created once, read back and changed only from the seal that was read", async () => {
			const store = await options.create();
			const tenant = tenantOf();

			expect(await store.getTenant(tenant.id)).toBeUndefined();
			expect(await store.createTenant(tenant)).toBe("created");
			expect(await store.createTenant({ ...tenant, seal: "other" })).toBe(
				"conflict",
			);
			expect(await store.getTenant(tenant.id)).toEqual(tenant);

			const disabled = { ...tenant, disabled: true, seal: unique("seal-") };

			expect(await store.setTenant(disabled, "not-the-seal")).toBe(false);
			expect(await store.setTenant(disabled, tenant.seal)).toBe(true);
			expect(await store.getTenant(tenant.id)).toEqual(disabled);

			const enabled = { ...tenant, seal: unique("seal-") };

			expect(await store.setTenant(enabled, tenant.seal)).toBe(false);
			expect(await store.setTenant(enabled, disabled.seal)).toBe(true);
			expect(await store.getTenant(tenant.id)).toEqual(enabled);
		});

		test("an account comes with its first identity and membership, and each is found again", async () => {
			const { store, tenant, create } = await setUp();
			const { account, identity, membership } = await create({
				email: uniqueEmail(),
				emailVerified: true,
			});

			expect(await store.getAccount(account.id)).toEqual(account);
			expect(
				await store.findIdentity(identity.provider, identity.externalId),
			).toEqual(identity);
			expect(await store.findMembership(tenant.id, account.id)).toEqual(
				membership,
			);
			expect(
				await store.getMembership(tenant.id, membership?.subjectId ?? ""),
			).toEqual(membership);
			expect(
				await store.getMembership(
					unique("tenant-"),
					membership?.subjectId ?? "",
				),
			).toBeUndefined();
			expect(await store.listMemberships(account.id)).toEqual([membership]);
			expect(
				await store.findIdentity("github", identity.externalId),
			).toBeUndefined();
		});

		test("the first writer of an identity wins, also when several write at once, and the losers leave nothing", async () => {
			const { store, tenant } = await setUp();
			const externalId = unique("person-");
			const attempts = Array.from({ length: 5 }, () => {
				const account = accountOf();

				return {
					account,
					identity: identityOf(account.id, { externalId }),
					membership: membershipOf(tenant.id, account.id),
				};
			});
			const results = await Promise.all(
				attempts.map((attempt) =>
					store.createAccount(
						attempt.account,
						attempt.identity,
						attempt.membership,
					),
				),
			);

			expect(results.filter((result) => result === "created")).toHaveLength(1);

			const owner = await store.findIdentity("email", externalId);

			for (const attempt of attempts) {
				const won = attempt.account.id === owner?.accountId;

				expect((await store.getAccount(attempt.account.id)) !== undefined).toBe(
					won,
				);
				expect(
					(await store.findMembership(tenant.id, attempt.account.id)) !==
						undefined,
				).toBe(won);
			}
		});

		test("an account whose membership names an unknown tenant is not created at all", async () => {
			const { store } = await setUp();
			const account = accountOf();
			const identity = identityOf(account.id);

			expect(
				await store.createAccount(
					account,
					identity,
					membershipOf(unique("tenant-"), account.id),
				),
			).toBe("conflict");
			expect(await store.getAccount(account.id)).toBeUndefined();
			expect(
				await store.findIdentity(identity.provider, identity.externalId),
			).toBeUndefined();
		});

		test("an identity is unique in the deployment, not per tenant", async () => {
			const { store, create } = await setUp();
			const other = tenantOf();

			expect(await store.createTenant(other)).toBe("created");

			const first = await create();
			const second = accountOf();

			expect(
				await store.createAccount(
					second,
					identityOf(second.id, { externalId: first.identity.externalId }),
					membershipOf(other.id, second.id),
				),
			).toBe("conflict");
		});

		test("linking adds an identity to a live account only, and the first link wins", async () => {
			const { store, create } = await setUp();
			const alice = await create();
			const bob = await create();
			const google = identityOf(alice.account.id, {
				provider: "google",
				externalId: unique("g-"),
			});

			expect(await store.linkIdentity(google)).toBe("linked");
			expect(await store.findIdentity("google", google.externalId)).toEqual(
				google,
			);
			expect(
				await store.linkIdentity({ ...google, accountId: bob.account.id }),
			).toBe("conflict");
			expect(
				await store.linkIdentity(identityOf(unique("acc_"), { provider: "x" })),
			).toBe("missing");
		});

		test("an identity changes only from the seal that was read", async () => {
			const { store, create } = await setUp();
			const { identity } = await create();
			const changed = {
				...identity,
				email: uniqueEmail(),
				emailVerified: true,
				seal: unique("seal-"),
			};

			expect(await store.updateIdentity(changed, "not-the-seal")).toBe(false);
			expect(await store.updateIdentity(changed, identity.seal)).toBe(true);
			expect(
				await store.findIdentity(identity.provider, identity.externalId),
			).toEqual(changed);
			expect(await store.updateIdentity(changed, identity.seal)).toBe(false);
		});

		test("a membership is unique for a tenant and an account, and needs a live account and a known tenant", async () => {
			const { store, tenant, create } = await setUp();
			const other = tenantOf();

			expect(await store.createTenant(other)).toBe("created");

			const { account, membership } = await create();
			const second = membershipOf(other.id, account.id);

			expect(await store.createMembership(second)).toBe("created");
			expect(
				await store.createMembership(membershipOf(tenant.id, account.id)),
			).toBe("conflict");
			expect(
				await store.createMembership(
					membershipOf(unique("tenant-"), account.id),
				),
			).toBe("conflict");
			expect(
				await store.createMembership(membershipOf(other.id, unique("acc_"))),
			).toBe("conflict");
			expect(
				await store.createMembership({
					...membershipOf(other.id, (await create({}, null)).account.id),
					subjectId: second.subjectId,
				}),
			).toBe("conflict");

			const listed = await store.listMemberships(account.id);

			expect(listed).toHaveLength(2);
			expect(listed).toEqual(expect.arrayContaining([membership, second]));
		});

		test("a membership changes only from the seal that was read, in its own tenant", async () => {
			const { store, tenant, create } = await setUp();
			const { membership } = await create();

			if (membership === undefined) {
				throw new Error("the account was created with a membership");
			}

			const suspended = {
				...membership,
				status: "suspended" as const,
				seal: unique("seal-"),
			};

			expect(await store.setMembership(suspended, "not-the-seal")).toBe(false);
			expect(
				await store.setMembership(
					{ ...suspended, tenant: unique("tenant-") },
					membership.seal,
				),
			).toBe(false);
			expect(await store.setMembership(suspended, membership.seal)).toBe(true);
			expect(
				await store.getMembership(tenant.id, membership.subjectId),
			).toEqual(suspended);
		});

		test("an account is sealed again from the seal that was read, and keeps its eviction mark", async () => {
			const { store, create } = await setUp();
			const { account } = await create();
			const resealed = { ...account, seal: unique("seal-") };

			expect(await store.setAccount(resealed, "not-the-seal")).toBe(false);
			expect(await store.setAccount(resealed, account.seal)).toBe(true);
			expect(await store.getAccount(account.id)).toEqual(resealed);
		});

		test("the owner of an email is the oldest identity of a listed provider that verified it", async () => {
			const { store, create } = await setUp();
			const email = uniqueEmail();

			await create({ email, emailVerified: false });

			const untrusted = await create({
				provider: "untrusted",
				email,
				emailVerified: true,
			});
			const first = await create({ email, emailVerified: true });

			await create({ email, emailVerified: true });

			expect((await store.findVerifiedOwner(email, ["email"]))?.accountId).toBe(
				first.account.id,
			);
			expect(
				(await store.findVerifiedOwner(email, ["untrusted", "email"]))
					?.accountId,
			).toBe(untrusted.account.id);
			expect(await store.findVerifiedOwner(email, ["other"])).toBeUndefined();
			expect(
				await store.findVerifiedOwner(uniqueEmail(), ["email"]),
			).toBeUndefined();
		});

		test("an eviction removes every claim that no trusted provider verified, from every other account, and marks the emptied ones", async () => {
			const { store, create } = await setUp();
			const email = uniqueEmail();
			const keeper = await create({ email, emailVerified: true });

			await store.linkIdentity(
				identityOf(keeper.account.id, {
					provider: "password",
					email,
					emailVerified: false,
				}),
			);

			const claimant = await create({ email, emailVerified: false });
			const untrusted = await create({
				provider: "untrusted",
				email,
				emailVerified: true,
			});
			const owner = await create({ email, emailVerified: true });
			const mixed = await create({ email, emailVerified: false });
			const kept = identityOf(mixed.account.id, {
				provider: "github",
				email: uniqueEmail(),
			});

			await store.linkIdentity(kept);

			const expected = [
				claimant.account.id,
				untrusted.account.id,
				mixed.account.id,
			];

			expect(
				await store.findEmailClaimants(email, keeper.account.id, ["email"]),
			).toEqual(expected);
			expect(
				await store.evictEmailClaims(email, keeper.account.id, ["email"]),
			).toEqual(expected);

			expect((await store.getAccount(claimant.account.id))?.evicted).toBe(true);
			expect((await store.getAccount(untrusted.account.id))?.evicted).toBe(
				true,
			);
			expect((await store.getAccount(mixed.account.id))?.evicted).toBe(false);
			expect((await store.getAccount(owner.account.id))?.evicted).toBe(false);
			expect((await store.getAccount(keeper.account.id))?.evicted).toBe(false);
			expect(
				await store.findIdentity("email", claimant.identity.externalId),
			).toBeUndefined();
			expect(await store.findIdentity("github", kept.externalId)).toEqual(kept);
			expect(
				await store.findIdentity("email", owner.identity.externalId),
			).toEqual(owner.identity);
			expect((await store.findVerifiedOwner(email, ["email"]))?.accountId).toBe(
				keeper.account.id,
			);
			expect(
				await store.findEmailClaimants(email, keeper.account.id, ["email"]),
			).toEqual([]);
			expect(
				await store.linkIdentity(
					identityOf(claimant.account.id, { provider: "x" }),
				),
			).toBe("missing");
			expect(
				await store.setAccount(
					{
						...claimant.account,
						evicted: false,
						seal: unique("seal-"),
					},
					claimant.account.seal,
				),
			).toBe(true);
			expect((await store.getAccount(claimant.account.id))?.evicted).toBe(true);
		});

		test("deleting an account takes its identities and leaves its subjects removed, without an account", async () => {
			const { store, tenant, create } = await setUp();
			const other = tenantOf();

			expect(await store.createTenant(other)).toBe("created");

			const { account, identity, membership } = await create();
			const second = membershipOf(other.id, account.id);

			await store.createMembership(second);

			const left = await store.deleteAccount(account.id);

			expect(left).toHaveLength(2);
			expect(left).toEqual(
				expect.arrayContaining(
					[membership, second].map((kept) => ({
						...kept,
						accountId: undefined,
						status: "removed",
					})),
				),
			);
			expect(await store.getAccount(account.id)).toBeUndefined();
			expect(
				await store.findIdentity(identity.provider, identity.externalId),
			).toBeUndefined();
			expect(await store.findMembership(tenant.id, account.id)).toBeUndefined();
			expect(
				await store.getMembership(tenant.id, membership?.subjectId ?? ""),
			).toEqual({
				...membership,
				accountId: undefined,
				status: "removed",
			});
			expect(await store.listMemberships(account.id)).toEqual([]);
			expect(await store.deleteAccount(account.id)).toBeUndefined();
			expect(await store.deleteAccount(unique("acc_"))).toBeUndefined();
		});

		test("deleting an account without memberships answers an empty list", async () => {
			const { store, create } = await setUp();
			const { account } = await create({}, null);

			expect(await store.deleteAccount(account.id)).toEqual([]);
		});
	});
}
