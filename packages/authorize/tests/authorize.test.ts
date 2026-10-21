import {
	buildAbility,
	createRules,
	defineAbilities,
	shape,
} from "@vetojs/core";
import { authorize, narrow } from "@vow-auth/authorize";
import type { AuditRecord, AuditSink } from "@vow-auth/core";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

type Post = {
	id: string;
	authorId: string;
	status: "draft" | "published";
	featured: boolean;
};

const ac = defineAbilities({
	resources: {
		post: {
			schema: shape<Post>(),
			actions: ["read", "update", "delete"],
			relations: { author: { resource: "user", kind: "one" } },
		},
		user: { schema: shape<{ id: string; role: string }>(), actions: ["read"] },
	},
});

const { allow, deny } = createRules(ac);

const post = (overrides: Partial<Post> = {}): Post => ({
	id: "p1",
	authorId: "u1",
	status: "published",
	featured: false,
	...overrides,
});

const silent: AuditSink = async () => undefined;
const context = { tenant: "acme", subject: "u1", audit: silent };

const collect = () => {
	const records: AuditRecord[] = [];
	const audit: AuditSink = async (record) => {
		records.push(record);
	};

	return { audit, records };
};

test("A11: nothing is allowed unless a rule allows it", async () => {
	const nothing = buildAbility(ac, []);
	const readOnly = buildAbility(ac, [allow("read", "post")]);

	for (const action of ["read", "update", "delete"] as const) {
		const result = await authorize(
			nothing,
			{ action, resource: "post", row: post() },
			context,
		);

		expect(!result.ok && result.error, action).toBe("forbidden");
	}

	expect(
		(
			await authorize(
				readOnly,
				{ action: "read", resource: "post", row: post() },
				context,
			)
		).ok,
	).toBe(true);
	expect(
		(
			await authorize(
				readOnly,
				{ action: "update", resource: "post", row: post() },
				context,
			)
		).ok,
	).toBe(false);
});

test("a check without a row passes only when no row could change the answer", async () => {
	const conditional = buildAbility(ac, [
		allow("read", "post", { where: { status: "published" } }),
	]);
	const unconditional = buildAbility(ac, [allow("read", "post")]);

	expect(
		(
			await authorize(
				conditional,
				{ action: "read", resource: "post" },
				context,
			)
		).ok,
	).toBe(false);
	expect(
		(
			await authorize(
				unconditional,
				{ action: "read", resource: "post" },
				context,
			)
		).ok,
	).toBe(true);
});

test("A18: a deny wins over an allow, and unknown data fires a deny and grants no allow", async () => {
	const ability = buildAbility(ac, [
		allow("read", "post"),
		deny("read", "post", { where: { status: "draft" } }),
	]);
	const incomplete = JSON.parse('{"id":"p1","authorId":"u1"}');

	const run = (row: Post) =>
		authorize(ability, { action: "read", resource: "post", row }, context);

	expect((await run(post({ status: "published" }))).ok).toBe(true);
	expect((await run(post({ status: "draft" }))).ok).toBe(false);
	expect((await run(incomplete)).ok).toBe(false);
});

test("an error while checking is a refusal, never an allow", async () => {
	const { audit, records } = collect();
	const ability = buildAbility(ac, [
		allow("read", "post", { where: { author: { role: "admin" } } }),
	]);

	const result = await authorize(
		ability,
		{ action: "read", resource: "post", row: post() },
		{ ...context, audit },
	);

	expect(!result.ok && result.error).toBe("forbidden");
	expect(records.map((record) => record.reason)).toEqual(["authorize-error"]);
});

test("every verdict is recorded with who asked and what", async () => {
	const { audit, records } = collect();
	const ability = buildAbility(ac, [allow("read", "post")]);

	await authorize(
		ability,
		{ action: "read", resource: "post", row: post() },
		{ ...context, audit },
	);
	await authorize(
		ability,
		{ action: "delete", resource: "post", row: post() },
		{ ...context, audit },
	);

	expect(
		records.map((record) => [record.event, record.outcome, record.reason]),
	).toEqual([
		["authorize.check", "success", "allowed"],
		["authorize.check", "refusal", "forbidden"],
	]);
	expect(records[0]).toMatchObject({
		tenant: "acme",
		subject: "u1",
		detail: { action: "read", resource: "post" },
	});
});

test("a failing sink means no allow", async () => {
	const ability = buildAbility(ac, [allow("read", "post")]);
	const audit: AuditSink = async () => {
		throw new Error("the audit store is down");
	};

	await expect(
		authorize(
			ability,
			{ action: "read", resource: "post", row: post() },
			{ ...context, audit },
		),
	).rejects.toThrow("the audit store is down");
});

test("A11: a delegation can only add denies", () => {
	const parent = buildAbility(ac, [allow("read", "post")]);

	expect(narrow(ac, parent, [deny("read", "post")]).ok).toBe(true);

	for (const rules of [
		[allow("update", "post")],
		[deny("read", "post"), allow("update", "post")],
	]) {
		const result = narrow(ac, parent, rules);

		expect(!result.ok && result.error).toBe("invalid-delegation");
	}
});

test("A12: the delegate keeps every restriction of the delegator and adds its own", async () => {
	const parent = buildAbility(ac, [
		allow("read", "post"),
		deny("read", "post", { where: { status: "draft" } }),
	]);
	const narrowed = narrow(ac, parent, [
		deny("read", "post", { where: { authorId: "u2" } }),
	]);

	if (!narrowed.ok) {
		throw new Error("the delegation must be accepted");
	}

	const delegate = narrowed.value;

	expect(delegate.can("read", "post", post())).toBe(true);
	expect(delegate.can("read", "post", post({ status: "draft" }))).toBe(false);
	expect(delegate.can("read", "post", post({ authorId: "u2" }))).toBe(false);
	expect(parent.can("read", "post", post({ authorId: "u2" }))).toBe(true);
});

const allows = [
	allow("read", "post"),
	allow("read", "post", { where: { status: "published" } }),
	allow(["update", "delete"], "post", { where: { authorId: "u1" } }),
	allow("manage", "post", { where: { authorId: "u2" } }),
];
const denies = [
	deny("update", "post", { where: { featured: true } }),
	deny("read", "post", { where: { status: "draft" } }),
	deny("delete", "post"),
	deny("read", "post", { where: { authorId: "u3" } }),
];

test("A19: whatever a delegate may do, its delegator may do, and every refusal of the delegator holds", () => {
	fastCheck.assert(
		fastCheck.property(
			fastCheck.subarray([...allows, ...denies]),
			fastCheck.subarray(denies),
			fastCheck.constantFrom("u1", "u2", "u3"),
			fastCheck.constantFrom("draft", "published"),
			fastCheck.boolean(),
			(parentRules, extraDenies, authorId, status, featured) => {
				const parent = buildAbility(ac, parentRules);
				const narrowed = narrow(ac, parent, extraDenies);

				if (!narrowed.ok) {
					throw new Error("denies must be accepted");
				}

				const row = post({ authorId, status, featured });

				for (const action of ["read", "update", "delete"] as const) {
					const parentMay = parent.can(action, "post", row);
					const delegateMay = narrowed.value.can(action, "post", row);

					expect(!delegateMay || parentMay, action).toBe(true);
				}
			},
		),
		{ numRuns: 500 },
	);
});
