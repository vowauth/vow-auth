import type { TokenStore } from "@vow-auth/core";
import {
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
	toNumber,
	toStringRecord,
	toText,
} from "./postgres-runner.js";

const PUT = `insert into vow_auth_tokens (hash, purpose, payload, expires_at_milliseconds)
	values ($1, $2, $3, $4)
	on conflict (hash) do update set
		purpose = excluded.purpose,
		payload = excluded.payload,
		expires_at_milliseconds = excluded.expires_at_milliseconds`;

const TAKE = `delete from vow_auth_tokens where hash = $1
	returning purpose, payload, expires_at_milliseconds`;

const PURGE = `with gone as (
	delete from vow_auth_tokens
	where expires_at_milliseconds <= ${SERVER_NOW_MILLISECONDS}
	returning 1
)
select count(*) as purged from gone`;

/** The token store, with the cleanup that Postgres does not do by itself. */
export type PostgresTokenStore = TokenStore & {
	/**
	 * Deletes the records that expired, by the server's clock, and says how
	 * many. Expiry is checked by the caller of \`take\`, so this is only garbage
	 * collection: run it from a schedule, as often as the table should be small.
	 */
	purgeExpired(): Promise<number>;
};

/**
 * Token store on Postgres. \`take\` is one \`delete ... returning\`, which
 * Postgres runs as a single atomic step: of any number of concurrent takes,
 * one receives the row. A committed \`put\` is visible to every connection, so
 * the store is strongly consistent; a failover to an asynchronous replica can
 * bring a taken record back within the replication lag, as the port requires
 * an adapter to document. Failures throw.
 */
export function createPostgresTokenStore(
	run: PostgresRunner,
): PostgresTokenStore {
	return {
		async put(hash, record) {
			await run(PUT, [
				hash,
				record.purpose,
				JSON.stringify(record.payload),
				record.expiresAtMilliseconds,
			]);
		},
		async take(hash) {
			const [row] = await run(TAKE, [hash]);

			if (row === undefined) {
				return undefined;
			}

			return {
				purpose: toText(row.purpose),
				payload: toStringRecord(row.payload),
				expiresAtMilliseconds: toNumber(row.expires_at_milliseconds),
			};
		},
		async purgeExpired() {
			const [row] = await run(PURGE, []);

			return row === undefined ? 0 : toNumber(row.purged);
		},
	};
}
