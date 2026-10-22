/** One row of a result, by column name. */
export type PostgresRow = Readonly<Record<string, unknown>>;

/**
 * Runs one SQL statement with positional parameters (`$1`, `$2`, ...) and
 * returns its rows, so the stores work with any client. Give the stores a
 * runner bound to a transaction to make them part of it.
 *
 * @example
 * pg: `async (text, parameters) => (await pool.query(text, [...parameters])).rows`
 * postgres.js: `(text, parameters) => sql.unsafe(text, [...parameters])`
 */
export type PostgresRunner = (
	text: string,
	parameters: readonly unknown[],
) => Promise<readonly PostgresRow[]>;

/** The server time in whole milliseconds, as a SQL expression. */
export const SERVER_NOW_MILLISECONDS =
	"floor(extract(epoch from clock_timestamp()) * 1000)::bigint";

/** Reads a number from a column that a client may return as a number, a bigint or a string. */
export const toNumber = (value: unknown): number => {
	if (typeof value === "number") {
		return value;
	}

	if (typeof value === "bigint") {
		return Number(value);
	}

	return typeof value === "string" ? Number(value) : Number.NaN;
};

/** Reads a text column. */
export const toText = (value: unknown): string => {
	if (typeof value !== "string") {
		throw new Error("The database must answer a text column with text");
	}

	return value;
};

/** Reads a payload column: JSON text of string values (a client that parses it for us is fine too). */
export const toStringRecord = (value: unknown): Record<string, string> => {
	const parsed: unknown = typeof value === "string" ? JSON.parse(value) : value;

	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new Error("The database must answer a payload with a JSON object");
	}

	const record: Record<string, string> = {};

	for (const [key, entry] of Object.entries(parsed)) {
		if (typeof entry !== "string") {
			throw new Error("A payload holds text values only");
		}

		record[key] = entry;
	}

	return record;
};
