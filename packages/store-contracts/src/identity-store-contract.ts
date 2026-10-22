import {
	type CanonicalEmail,
	canonicalizeEmail,
	type IdentityClaims,
	type IdentityStore,
} from "@vow-auth/core";
import { describe, expect, test } from "vitest";

/** What an adapter gives the identity contract. */
export type IdentityStoreContractOptions = {
	readonly create: () => IdentityStore | Promise<IdentityStore>;
};

const emailOf = (address: string): CanonicalEmail => {
	const email = canonicalizeEmail(address);

	if (email === undefined) {
		throw new Error(`the test address ${address} must be valid`);
	}

	return email;
};

const verified = (
	provider: string,
	externalId: string,
	address: string,
): IdentityClaims => ({
	provider,
	externalId,
	email: emailOf(address),
	emailVerified: true,
});

const unverified = (
	provider: string,
	externalId: string,
	address?: string,
): IdentityClaims =>
	address === undefined
		? { provider, externalId, emailVerified: false }
		: {
				provider,
				externalId,
				email: emailOf(address),
				emailVerified: false,
			};

const uniqueTenant = (): string => `tenant-${crypto.randomUUID()}`;

/**
 * Defines the tests every `IdentityStore` must pass: the first writer of an
 * identity wins, a tenant never reaches another tenant, unverified claims are
 * kept apart from the verified owner of an email, and deleting a subject
 * leaves nothing that finds it. Call it inside a test file once per adapter.
 */
export function identityStoreContract(
	name: string,
	options: IdentityStoreContractOptions,
): void {
	describe(`${name}: the identity store contract`, () => {
		test("a created subject is found by its identity and by its verified email", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const claims = verified("email", "alice", "alice@example.com");
			const created = await store.createSubject(tenant, claims);

			expect(created.isNew).toBe(true);
			expect(await store.findSubject(tenant, "email", "alice")).toBe(
				created.subjectId,
			);
			expect(
				await store.findSubjectByVerifiedEmail(
					tenant,
					emailOf("alice@example.com"),
				),
			).toBe(created.subjectId);
			expect(await store.findSubject(tenant, "email", "bob")).toBeUndefined();
			expect(
				await store.findSubject(tenant, "github", "alice"),
			).toBeUndefined();
		});

		test("the first writer of an identity wins, also when two write at once", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const claims = verified("email", "alice", "alice@example.com");
			const results = await Promise.all(
				Array.from({ length: 5 }, () => store.createSubject(tenant, claims)),
			);
			const owners = new Set(results.map((result) => result.subjectId));

			expect(owners.size).toBe(1);
			expect(results.filter((result) => result.isNew)).toHaveLength(1);
			expect(await store.findSubject(tenant, "email", "alice")).toBe(
				[...owners][0],
			);
		});

		test("linking adds an identity to a subject and returns the owner when it is taken", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const alice = await store.createSubject(
				tenant,
				verified("email", "alice", "alice@example.com"),
			);
			const bob = await store.createSubject(
				tenant,
				verified("email", "bob", "bob@example.com"),
			);

			expect(
				await store.linkIdentity(
					tenant,
					alice.subjectId,
					verified("google", "g-1", "alice@example.com"),
				),
			).toBe(alice.subjectId);
			expect(await store.findSubject(tenant, "google", "g-1")).toBe(
				alice.subjectId,
			);
			expect(
				await store.linkIdentity(
					tenant,
					bob.subjectId,
					verified("google", "g-1", "alice@example.com"),
				),
			).toBe(alice.subjectId);
		});

		test("the first verified owner of an email keeps it", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const first = await store.createSubject(
				tenant,
				verified("email", "one", "shared@example.com"),
			);

			await store.createSubject(
				tenant,
				verified("google", "two", "shared@example.com"),
			);

			expect(
				await store.findSubjectByVerifiedEmail(
					tenant,
					emailOf("shared@example.com"),
				),
			).toBe(first.subjectId);
		});

		test("when the owner of a verified email is deleted the next verified owner, in order of arrival, is found", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const email = emailOf("shared@example.com");
			const first = await store.createSubject(
				tenant,
				verified("email", "one", "shared@example.com"),
			);
			const second = await store.createSubject(
				tenant,
				verified("google", "two", "shared@example.com"),
			);
			const third = await store.createSubject(
				tenant,
				verified("github", "three", "shared@example.com"),
			);

			expect(await store.findSubjectByVerifiedEmail(tenant, email)).toBe(
				first.subjectId,
			);

			await store.deleteSubject(tenant, first.subjectId);

			expect(await store.findSubjectByVerifiedEmail(tenant, email)).toBe(
				second.subjectId,
			);

			await store.deleteSubject(tenant, second.subjectId);

			expect(await store.findSubjectByVerifiedEmail(tenant, email)).toBe(
				third.subjectId,
			);

			await store.deleteSubject(tenant, third.subjectId);

			expect(
				await store.findSubjectByVerifiedEmail(tenant, email),
			).toBeUndefined();
		});

		test("a tenant never reaches the subjects, identities or emails of another", async () => {
			const store = await options.create();
			const acme = uniqueTenant();
			const globex = uniqueTenant();
			const claims = verified("email", "alice", "alice@example.com");
			const inAcme = await store.createSubject(acme, claims);
			const inGlobex = await store.createSubject(globex, claims);

			expect(inGlobex.isNew).toBe(true);
			expect(inGlobex.subjectId).not.toBe(inAcme.subjectId);
			expect(await store.deleteSubject(globex, inAcme.subjectId)).toBe(false);
			expect(await store.findSubject(acme, "email", "alice")).toBe(
				inAcme.subjectId,
			);
			expect(await store.deleteSubject(acme, inGlobex.subjectId)).toBe(false);
			expect(
				await store.findSubjectByVerifiedEmail(
					globex,
					emailOf("alice@example.com"),
				),
			).toBe(inGlobex.subjectId);
		});

		test("an unverified claim is listed for its email and never counts as the owner", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const squatter = await store.createSubject(
				tenant,
				unverified("evil", "e-1", "victim@example.com"),
			);
			const email = emailOf("victim@example.com");

			expect(await store.findSubjectByVerifiedEmail(tenant, email)).toBe(
				undefined,
			);
			expect(await store.findSubjectsByUnverifiedEmail(tenant, email)).toEqual([
				squatter.subjectId,
			]);
			expect(
				await store.findSubjectsByUnverifiedEmail(uniqueTenant(), email),
			).toEqual([]);
		});

		test("removing unverified claims spares the kept subject and the verified owner, and deletes the emptied ones", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const address = "victim@example.com";
			const email = emailOf(address);
			const squatter = await store.createSubject(
				tenant,
				unverified("evil", "e-1", address),
			);
			const mixed = await store.createSubject(
				tenant,
				verified("email", "mixed", "mixed@example.com"),
			);

			await store.linkIdentity(
				tenant,
				mixed.subjectId,
				unverified("other", "o-1", address),
			);

			const owner = await store.createSubject(
				tenant,
				verified("email", "victim", address),
			);
			const touched = await store.removeUnverifiedEmailClaims(
				tenant,
				email,
				owner.subjectId,
			);

			expect([...touched].sort()).toEqual(
				[squatter.subjectId, mixed.subjectId].sort(),
			);
			expect(await store.findSubject(tenant, "evil", "e-1")).toBeUndefined();
			expect(await store.findSubject(tenant, "other", "o-1")).toBeUndefined();
			expect(await store.findSubject(tenant, "email", "mixed")).toBe(
				mixed.subjectId,
			);
			expect(await store.findSubject(tenant, "email", "victim")).toBe(
				owner.subjectId,
			);
			expect(await store.findSubjectsByUnverifiedEmail(tenant, email)).toEqual(
				[],
			);
			expect(await store.deleteSubject(tenant, squatter.subjectId)).toBe(false);
		});

		test("removing claims of another tenant touches nothing", async () => {
			const store = await options.create();
			const acme = uniqueTenant();
			const address = "victim@example.com";
			const squatter = await store.createSubject(
				acme,
				unverified("evil", "e-1", address),
			);

			expect(
				await store.removeUnverifiedEmailClaims(
					uniqueTenant(),
					emailOf(address),
					crypto.randomUUID(),
				),
			).toEqual([]);
			expect(await store.findSubject(acme, "evil", "e-1")).toBe(
				squatter.subjectId,
			);
		});

		test("deleting a subject leaves nothing that finds it", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const alice = await store.createSubject(
				tenant,
				verified("email", "alice", "alice@example.com"),
			);

			await store.linkIdentity(
				tenant,
				alice.subjectId,
				unverified("github", "gh-1", "alice-work@example.com"),
			);

			expect(await store.deleteSubject(tenant, alice.subjectId)).toBe(true);
			expect(await store.findSubject(tenant, "email", "alice")).toBeUndefined();
			expect(await store.findSubject(tenant, "github", "gh-1")).toBeUndefined();
			expect(
				await store.findSubjectByVerifiedEmail(
					tenant,
					emailOf("alice@example.com"),
				),
			).toBeUndefined();
			expect(
				await store.findSubjectsByUnverifiedEmail(
					tenant,
					emailOf("alice-work@example.com"),
				),
			).toEqual([]);
			expect(await store.deleteSubject(tenant, alice.subjectId)).toBe(false);
		});

		test("an identity freed by a deletion can be created again as a new subject", async () => {
			const store = await options.create();
			const tenant = uniqueTenant();
			const claims = verified("email", "alice", "alice@example.com");
			const first = await store.createSubject(tenant, claims);

			await store.deleteSubject(tenant, first.subjectId);

			const second = await store.createSubject(tenant, claims);

			expect(second.isNew).toBe(true);
			expect(second.subjectId).not.toBe(first.subjectId);
		});
	});
}
