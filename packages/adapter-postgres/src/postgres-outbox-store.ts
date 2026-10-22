import type { OutboxRecord, OutboxStore } from "@vow-auth/core";
import {
	type PostgresRunner,
	SERVER_NOW_MILLISECONDS,
	toNumber,
	toStringRecord,
	toText,
} from "./postgres-runner.js";

const APPEND = `insert into vow_auth_outbox (id, type, payload)
	values ($1, $2, $3)
	on conflict (id) do nothing`;

const CLAIM = `update vow_auth_outbox
	set attempts = attempts + 1,
		available_at_milliseconds = ${SERVER_NOW_MILLISECONDS} + $2
	where seq in (
		select seq from vow_auth_outbox
		where available_at_milliseconds <= ${SERVER_NOW_MILLISECONDS}
		order by seq
		limit $1
		for update skip locked
	)
	returning seq, id, type, payload, attempts`;

const COMPLETE = `delete from vow_auth_outbox where id = $1 and attempts = $2`;

const RELEASE = `update vow_auth_outbox
	set available_at_milliseconds = ${SERVER_NOW_MILLISECONDS} + $3
	where id = $1 and attempts = $2`;

const BURY = `with gone as (
	delete from vow_auth_outbox where id = $1 and attempts = $2
	returning id, type, payload, attempts
)
insert into vow_auth_outbox_buried
	(id, type, payload, attempts, buried_at_milliseconds)
select id, type, payload, attempts, ${SERVER_NOW_MILLISECONDS} from gone`;

/**
 * Outbox store on Postgres. Give \`append\` a runner bound to the transaction
 * that makes the change, so the event commits with it or not at all; the
 * worker uses a store on an ordinary connection. \`claim\` is one statement:
 * it picks the due rows with \`for update skip locked\`, so concurrent workers
 * never get the same row, and sets a lease by the server's clock, so a row
 * whose worker died is due again after the lease. \`complete\`, \`release\` and
 * \`bury\` match the \`attempts\` they were given, so a worker whose lease ran
 * out cannot undo a newer claim. Appending an id that exists changes
 * nothing. A buried event moves to \`vow_auth_outbox_buried\` for inspection.
 */
export function createPostgresOutboxStore(run: PostgresRunner): OutboxStore {
	return {
		async append(record) {
			await run(APPEND, [
				record.id,
				record.type,
				JSON.stringify(record.payload),
			]);
		},
		async claim(input) {
			const rows = await run(CLAIM, [input.limit, input.leaseMilliseconds]);

			return rows
				.map((row) => ({
					order: toNumber(row.seq),
					record: {
						id: toText(row.id),
						type: toText(row.type),
						payload: toStringRecord(row.payload),
						attempts: toNumber(row.attempts),
					} satisfies OutboxRecord,
				}))
				.sort((left, right) => left.order - right.order)
				.map(({ record }) => record);
		},
		async complete(record) {
			await run(COMPLETE, [record.id, record.attempts]);
		},
		async release(record, retryDelayMilliseconds) {
			await run(RELEASE, [record.id, record.attempts, retryDelayMilliseconds]);
		},
		async bury(record) {
			await run(BURY, [record.id, record.attempts]);
		},
	};
}
