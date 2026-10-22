import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { isPlainObject } from "../shared/is-plain-object.js";
import { isStorableText } from "../shared/is-storable-text.js";
import { own } from "../shared/own.js";
import type { DomainEvent, OutboxStore } from "./outbox-store.js";

const EVENT_KEYS: readonly string[] = ["type", "payload"];

type ParsedEvent = {
	readonly type: string;
	readonly payload: Readonly<Record<string, string>>;
};

const parseEvent = (raw: unknown): ParsedEvent | undefined => {
	if (!isPlainObject(raw)) {
		return undefined;
	}

	for (const key of Object.keys(raw)) {
		if (!EVENT_KEYS.includes(key)) {
			return undefined;
		}
	}

	const type = own(raw, "type");
	const payload = own(raw, "payload") ?? {};

	if (!isStorableText(type) || !isPlainObject(payload)) {
		return undefined;
	}

	const entries: [string, string][] = [];

	for (const [key, value] of Object.entries(payload)) {
		if (typeof value !== "string") {
			return undefined;
		}

		entries.push([key, value]);
	}

	return { type, payload: Object.fromEntries(entries) };
};

/** Records a domain event. It returns the id the event will carry to its handler. */
export type Emit = (event: DomainEvent) => Promise<Result<string>>;

/**
 * Creates `emit`, the only way out of the request path. It writes the event
 * to the outbox and returns; it never calls the outside world, so a slow or
 * failing recipient cannot slow down or break a sign-in. The event is checked
 * against a closed shape, so a misspelled key is refused instead of silently
 * dropping data, and copied with own properties only: a payload key such as
 * `__proto__` stays an ordinary key and never reaches a prototype. Delivery is
 * at least once, so handlers must tolerate the same id twice.
 */
export function createEmit(store: OutboxStore): Emit {
	return async (event) => {
		const parsed = parseEvent(event);

		if (parsed === undefined) {
			return fail(ERROR_CODES.invalidEvent);
		}

		const id = crypto.randomUUID();

		await store.append({ id, type: parsed.type, payload: parsed.payload });

		return succeed(id);
	};
}
