import {
	createPostgresIdentityStore,
	createPostgresSchema,
	createPostgresTokenStore,
	type PostgresRunner,
} from "@vow-auth/adapter-postgres";
import {
	identityStoreContract,
	type StoreClock,
	tokenStoreContract,
} from "@vow-auth/store-contracts";
import pg from "pg";
import { afterAll, beforeAll, describe } from "vitest";

const databaseUrl = process.env.VOW_AUTH_POSTGRES_URL;

describe.runIf(databaseUrl !== undefined)("postgres", () => {
	const SCHEMA = "vow_test_contracts";
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

	const clock: StoreClock = {
		now: async () => {
			const result = await pool.query(
				"select floor(extract(epoch from clock_timestamp()) * 1000)::bigint as now",
			);

			return Number(result.rows[0]?.now);
		},
		advance: (milliseconds) =>
			new Promise((resolve) => setTimeout(resolve, milliseconds)),
	};

	identityStoreContract("postgres", {
		create: () => createPostgresIdentityStore(run),
	});

	tokenStoreContract("postgres", {
		create: () => createPostgresTokenStore(run),
		clock,
	});
});
