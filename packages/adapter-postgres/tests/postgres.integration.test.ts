import {
	createMemoryEpochStore,
	createMemoryMeterStore,
} from "@vow-auth/adapter-memory";
import {
	createPostgresAccountStore,
	createPostgresSchema,
	createPostgresTokenStore,
	POSTGRES_SCHEMA,
	type PostgresRunner,
} from "@vow-auth/adapter-postgres";
import { createAuth, succeed } from "@vow-auth/core";
import { factorPluginOf } from "@vow-auth/test-support";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

const databaseUrl = process.env.VOW_AUTH_POSTGRES_URL;
const HOUR = 3_600_000;

describe.runIf(databaseUrl !== undefined)("postgres specifics", () => {
	const SCHEMA = "vow_test_specifics";
	const admin = new pg.Pool({ connectionString: databaseUrl, max: 1 });
	const pool = new pg.Pool({
		connectionString: databaseUrl,
		max: 40,
		options: `-c search_path=${SCHEMA}`,
	});

	const run: PostgresRunner = async (text, parameters) => {
		const result = await pool.query(text, [...parameters]);

		return result.rows;
	};

	beforeAll(async () => {
		await admin.query(`drop schema if exists ${SCHEMA} cascade`);
		await admin.query(`create schema ${SCHEMA}`);
		await createPostgresSchema(run);
	});

	const textOf = (response: unknown, key: string): string =>
		String(Reflect.get(Object(response), key) ?? "");

	/** The engine on these tables, with a tenant of its own. */
	const createEngine = async () => {
		const tenant = `tenant-${crypto.randomUUID()}`;
		const auth = createAuth({
			factors: {
				email: factorPluginOf(
					async (response) =>
						succeed({
							provider: "email",
							externalId: textOf(response, "email"),
							email: textOf(response, "email"),
							emailVerified: true,
						}),
					{ providers: ["email"] },
				),
				password: factorPluginOf(
					async (response) =>
						succeed({
							provider: "password",
							externalId: textOf(response, "email"),
							email: textOf(response, "email"),
							emailVerified: false,
						}),
					{ providers: ["password"] },
				),
			},
			accounts: createPostgresAccountStore(run),
			tokenStore: createPostgresTokenStore(run),
			epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
			meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
			secrets: [
				{ version: 1, value: "postgres-secret-0123456789abcdefghijkl" },
			],
			maximumLifeTimeMilliseconds: HOUR,
			sessionTimeToLiveMilliseconds: HOUR,
			registration: () => "allow",
			policy: () => "allow",
			audit: async () => undefined,
		});

		expect((await auth.tenants.create(tenant)).ok).toBe(true);

		const signIn = (factor: string, email: string, device = "laptop") =>
			auth.signIn({ tenant, device, factor, response: { email } });

		return { auth, tenant, signIn };
	};

	const countOf = async (statement: string, parameters: unknown[]) => {
		const result = await pool.query(statement, parameters);

		return Number(result.rows[0]?.count);
	};

	afterAll(async () => {
		await pool.end();
		await admin.end();
	});

	test("the schema can be created again and again", async () => {
		await createPostgresSchema(run);
		await createPostgresSchema(run);
	});

	test("the schema text works as a migration in a schema of its own", async () => {
		const client = await pool.connect();

		try {
			await client.query("create schema vow_schema_probe");
			await client.query("set search_path to vow_schema_probe");
			await client.query(POSTGRES_SCHEMA);

			const tables = await client.query(
				"select table_name from information_schema.tables where table_schema = 'vow_schema_probe' order by table_name",
			);

			expect(tables.rows.map((row) => row.table_name)).toEqual([
				"vow_auth_accounts",
				"vow_auth_identities",
				"vow_auth_subjects",
				"vow_auth_tenants",
				"vow_auth_tokens",
			]);
		} finally {
			await client.query("reset search_path");
			await client.query("drop schema vow_schema_probe cascade");
			client.release();
		}
	});

	test("parallel first sign ins of one person leave exactly one account and one subject", async () => {
		const { signIn, tenant } = await createEngine();
		const email = `${crypto.randomUUID()}@example.com`;
		const results = await Promise.all(
			Array.from({ length: 16 }, (_, index) =>
				signIn("email", email, `device-${index}`),
			),
		);

		expect(results.some((result) => result.ok)).toBe(true);
		expect(
			results.every((result) => result.ok || result.error === "conflict"),
		).toBe(true);
		expect(
			await countOf(
				"select count(*)::int as count from vow_auth_identities where provider = 'email' and external_id = $1",
				[email],
			),
		).toBe(1);
		expect(
			await countOf(
				"select count(*)::int as count from vow_auth_subjects where tenant = $1",
				[tenant],
			),
		).toBe(1);
		expect(
			await countOf(
				"select count(*)::int as count from vow_auth_accounts as account where not exists (select 1 from vow_auth_identities as identity where identity.account_id = account.id)",
				[],
			),
		).toBe(0);
	});

	test("a foreign key of the application blocks neither an eviction nor the deletion of an account, and loses no rows to them", async () => {
		const { auth, signIn } = await createEngine();
		const email = `${crypto.randomUUID()}@example.com`;

		await pool.query(`create table if not exists app_notes (
			subject_id text not null references vow_auth_subjects (id) on delete restrict
		)`);

		const squatter = await signIn("password", email);
		const owner = await signIn("email", email);

		if (!squatter.ok || !owner.ok) {
			throw new Error("both sign ins must pass");
		}

		expect(owner.value.evicted).toEqual([squatter.value.account]);

		await pool.query("insert into app_notes values ($1), ($2)", [
			squatter.value.subject,
			owner.value.subject,
		]);

		const deleted = await auth.accounts.delete(owner.value.account);

		expect(deleted.ok && deleted.value).toEqual([
			{
				tenant: owner.value.tenant,
				subject: owner.value.subject,
				status: "removed",
			},
		]);
		expect(
			await countOf(
				"select count(*)::int as count from app_notes where subject_id = any($1)",
				[[squatter.value.subject, owner.value.subject]],
			),
		).toBe(2);
		expect(
			await countOf(
				"select count(*)::int as count from vow_auth_subjects where id = $1 and account_id is null and status = 'removed'",
				[owner.value.subject],
			),
		).toBe(1);
		expect(
			await countOf(
				"select count(*)::int as count from vow_auth_accounts where id = $1 and evicted_at_milliseconds is not null",
				[squatter.value.account],
			),
		).toBe(1);
	});

	test("purging removes the expired tokens by the server's clock and keeps the rest", async () => {
		const store = createPostgresTokenStore(run);
		const now = Date.now();
		const expired = `expired-${crypto.randomUUID()}`;
		const living = `living-${crypto.randomUUID()}`;

		await store.put(expired, {
			purpose: "email-link",
			payload: { email: "a@example.com" },
			expiresAtMilliseconds: now - HOUR,
		});
		await store.put(living, {
			purpose: "email-link",
			payload: { email: "a@example.com" },
			expiresAtMilliseconds: now + HOUR,
		});

		expect(await store.purgeExpired()).toBeGreaterThanOrEqual(1);
		expect(await store.take(expired)).toBeUndefined();
		expect(await store.take(living)).toMatchObject({ purpose: "email-link" });
	});

	test("a token with an awkward payload comes back as it went in", async () => {
		const store = createPostgresTokenStore(run);
		const hash = `awkward-${crypto.randomUUID()}`;
		const payload = {
			'quote"key': "it's \\ a 'test' \u0000-free",
			emoji: "🙂",
			empty: "",
			__proto__: "kept as a key",
		};

		await store.put(hash, {
			purpose: "p",
			payload,
			expiresAtMilliseconds: Date.now() + HOUR,
		});

		expect((await store.take(hash))?.payload).toEqual(payload);
	});

	test("a sign in with a name the database cannot hold is a refusal, never a database error", async () => {
		const auth = createAuth({
			factors: {
				idp: factorPluginOf(
					async (response) =>
						succeed({
							provider: "idp",
							externalId: Reflect.get(Object(response), "externalId"),
							emailVerified: false,
						}),
					{ providers: ["idp"] },
				),
			},
			accounts: createPostgresAccountStore(run),
			tokenStore: createPostgresTokenStore(run),
			epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
			meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
			secrets: [
				{ version: 1, value: "postgres-secret-0123456789abcdefghijkl" },
			],
			maximumLifeTimeMilliseconds: HOUR,
			sessionTimeToLiveMilliseconds: HOUR,
			registration: () => "allow",
			policy: () => "allow",
			audit: async () => undefined,
		});

		await auth.tenants.create("acme");

		const NUL = String.fromCharCode(0);
		const LONE_SURROGATE = String.fromCharCode(0xd800);
		const attempts = [
			{ tenant: `acme${NUL}`, device: "laptop", externalId: "alice" },
			{ tenant: "acme", device: `lap${NUL}top`, externalId: "alice" },
			{ tenant: "acme", device: "laptop", externalId: `al${NUL}ice` },
			{
				tenant: "acme",
				device: "laptop",
				externalId: `al${LONE_SURROGATE}ice`,
			},
		];

		for (const { tenant, device, externalId } of attempts) {
			const result = await auth.signIn({
				tenant,
				device,
				factor: "idp",
				response: { externalId },
			});

			expect(result.ok, JSON.stringify({ tenant, device, externalId })).toBe(
				false,
			);
		}

		expect(
			(
				await auth.signIn({
					tenant: "acme",
					device: "Ivan's 👩‍💻 laptop",
					factor: "idp",
					response: { externalId: "alice" },
				})
			).ok,
		).toBe(true);
	});
});
