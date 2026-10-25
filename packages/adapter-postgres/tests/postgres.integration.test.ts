import {
	createMemoryEpochStore,
	createMemoryMeterStore,
} from "@vow-auth/adapter-memory";
import {
	createPostgresIdentityStore,
	createPostgresSchema,
	createPostgresTokenStore,
	POSTGRES_SCHEMA,
	type PostgresRunner,
} from "@vow-auth/adapter-postgres";
import {
	canonicalizeEmail,
	createAuth,
	type Factor,
	succeed,
} from "@vow-auth/core";
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
		await admin.query(`create schema if not exists ${SCHEMA}`);
		await createPostgresSchema(run);
	});

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
				"vow_auth_identities",
				"vow_auth_subjects",
				"vow_auth_tokens",
			]);
		} finally {
			await client.query("reset search_path");
			await client.query("drop schema vow_schema_probe cascade");
			client.release();
		}
	});

	test("parallel sign-ins of one identity leave exactly one subject", async () => {
		const store = createPostgresIdentityStore(run);
		const tenant = `tenant-${crypto.randomUUID()}`;
		const claims = {
			provider: "email",
			externalId: "alice",
			emailVerified: false,
		} as const;

		await Promise.all(
			Array.from({ length: 16 }, () => store.createSubject(tenant, claims)),
		);

		const subjects = await pool.query(
			"select count(*)::int as count from vow_auth_subjects where tenant = $1",
			[tenant],
		);

		expect(subjects.rows[0]?.count).toBe(1);
	});

	test("a foreign key of the application neither blocks an eviction nor loses its rows to it", async () => {
		const store = createPostgresIdentityStore(run);
		const tenant = `tenant-${crypto.randomUUID()}`;
		const email = canonicalizeEmail("victim@example.com");

		if (email === undefined) {
			throw new Error("the test address must be valid");
		}

		await pool.query(`create table if not exists app_notes (
			subject_id text not null references vow_auth_subjects (id) on delete restrict
		)`);
		await pool.query(`create table if not exists app_profiles (
			subject_id text primary key references vow_auth_subjects (id) on delete cascade
		)`);

		const squatter = await store.createSubject(tenant, {
			provider: "evil",
			externalId: `e-${crypto.randomUUID()}`,
			email,
			emailVerified: false,
		});
		const owner = await store.createSubject(tenant, {
			provider: "email",
			externalId: `victim-${crypto.randomUUID()}`,
			email,
			emailVerified: true,
		});

		await pool.query("insert into app_notes values ($1)", [squatter.subjectId]);
		await pool.query("insert into app_profiles values ($1)", [owner.subjectId]);

		expect(
			await store.removeUnverifiedEmailClaims(tenant, email, owner.subjectId),
		).toEqual([squatter.subjectId]);

		const notes = await pool.query(
			"select count(*)::int as count from app_notes where subject_id = $1",
			[squatter.subjectId],
		);

		expect(notes.rows[0]?.count).toBe(1);
		expect(
			(await store.getSubject(tenant, squatter.subjectId))
				?.evictedAtMilliseconds,
		).toEqual(expect.any(Number));
		expect(await store.deleteSubject(tenant, owner.subjectId)).toBe(true);

		const profiles = await pool.query(
			"select count(*)::int as count from app_profiles where subject_id = $1",
			[owner.subjectId],
		);

		expect(profiles.rows[0]?.count).toBe(0);
		await expect(
			store.deleteSubject(tenant, squatter.subjectId),
		).rejects.toThrow();
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
			identities: createPostgresIdentityStore(run),
			tokenStore: createPostgresTokenStore(run),
			epochs: createMemoryEpochStore({ maximumBytes: 1_000_000 }),
			meterStore: createMemoryMeterStore({ maximumBytes: 1_000_000 }),
			secrets: [
				{ version: 1, value: "postgres-secret-0123456789abcdefghijkl" },
			],
			maximumLifeTimeMilliseconds: HOUR,
			sessionTimeToLiveMilliseconds: HOUR,
			policy: () => "allow",
			audit: async () => undefined,
		});
		const factorFor = (externalId: string): Factor => ({
			id: "idp",
			strength: "possession",
			verify: async () =>
				succeed({ provider: "idp", externalId, emailVerified: false }),
		});
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
				factor: factorFor(externalId),
				response: {},
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
					factor: factorFor("alice"),
					response: {},
				})
			).ok,
		).toBe(true);
	});
});
