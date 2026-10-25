import {
	createMemoryMeterStore,
	createMemoryTokenStore,
} from "@vow-auth/adapter-memory";
import { defineDuration, defineMeterRule } from "@vow-auth/core";
import {
	createMeter,
	createSealer,
	createTokens,
} from "@vow-auth/core/internal";
import fastCheck from "fast-check";
import { expect, test } from "vitest";

const anyNumber = fastCheck.oneof(
	fastCheck.double({ noNaN: false }),
	fastCheck.integer(),
	fastCheck.constantFrom(
		Number.NaN,
		Number.POSITIVE_INFINITY,
		Number.NEGATIVE_INFINITY,
		0,
		-0,
		1.5,
		Number.MAX_SAFE_INTEGER,
		Number.MAX_SAFE_INTEGER + 1,
		Number.MAX_VALUE,
		Number.MIN_VALUE,
	),
);

test("A26: defining a duration never throws, and a duration it accepts never makes issuing or sealing throw", async () => {
	const tokens = createTokens({
		store: createMemoryTokenStore({ maximumBytes: 10_000_000 }),
	});
	const sealer = createSealer({
		secrets: [{ version: 1, value: "definitions-secret-0123456789abcdefg" }],
	});

	await fastCheck.assert(
		fastCheck.asyncProperty(anyNumber, async (milliseconds) => {
			const defined = defineDuration(milliseconds);

			if (!defined.ok) {
				expect(defined.error).toBe("invalid-request");

				return;
			}

			await expect(
				tokens.issue({ purpose: "email-link", timeToLive: defined.value }),
			).resolves.toEqual(expect.any(String));
			await expect(
				sealer.seal({ purpose: "oauth-state", timeToLive: defined.value }),
			).resolves.toEqual(expect.any(String));
		}),
		{ numRuns: 500 },
	);
});

test("A26: defining a meter rule never throws, and a rule it accepts never makes a request throw, whatever the cost", async () => {
	const meter = createMeter({
		store: createMemoryMeterStore({ maximumBytes: 10_000_000 }),
	});
	const scope = { tenant: "acme", actor: "alice", resource: "email-link" };

	await fastCheck.assert(
		fastCheck.asyncProperty(
			anyNumber,
			anyNumber,
			fastCheck.option(anyNumber, { nil: undefined }),
			async (limit, windowMilliseconds, cost) => {
				const defined = defineMeterRule({ limit, windowMilliseconds });

				if (!defined.ok) {
					expect(defined.error).toBe("invalid-request");

					return;
				}

				const consumed = await meter.consume(scope, defined.value, cost);

				expect(typeof consumed.ok).toBe("boolean");
			},
		),
		{ numRuns: 500 },
	);
});
