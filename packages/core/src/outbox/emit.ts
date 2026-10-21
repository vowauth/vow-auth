import { ERROR_CODES } from "../errors.js";
import { fail, type Result, succeed } from "../result.js";
import { isRow } from "../shared/is-row.js";
import { own } from "../shared/own.js";
import type { DomainEvent, OutboxStore } from "./outbox-store.js";

const EVENT_KEYS: readonly string[] = ["type", "payload"];

const parseEvent = (
	raw: unknown,
):
	| { readonly type: string; readonly payload: Record<string, string> }
	| undefined => {
	if (!isRow(raw)) {
		return undefined;
	}

	for (const key of Object.keys(raw)) {
		if (!EVENT_KEYS.includes(key)) {
			return undefined;
		}
	}

	const type = own(raw, "type");
	const payload = own(raw, "payload") ?? {};

	if (typeof type !== "string" || type.length === 0 || !isRow(payload)) {
		return undefined;
	}

	const copy: Record<string, string> = {};

	for (const [key, value] of Object.entries(payload)) {
		if (typeof value !== "string") {
			return undefined;
		}

		copy[key] = value;
	}

	return { type, payload: copy };
};

/** Records a domain event. It returns the id the event will carry to its handler. */
export type Emit = (event: DomainEvent) => Promise<Result<string>>;

/**
 * Creates `emit`, the only way out of the request path. It writes the event
 * to the outbox and returns; it never calls the outside world, so a slow or
 * failing recipient cannot slow down or break a sign-in. The event is checked
 * against a closed shape and copied. Delivery is at least once, so handlers
 * must tolerate the same id twice.
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
