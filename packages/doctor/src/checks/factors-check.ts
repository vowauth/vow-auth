import type { Factor } from "@vow-auth/core";
import type { Check, Finding } from "../finding.js";

const NO_EVIDENCE: readonly unknown[] = [
	undefined,
	null,
	{},
	[],
	"",
	0,
	false,
	"x",
	{ token: "" },
	{ code: "" },
	JSON.parse('{"__proto__":{"emailVerified":true}}'),
	{
		provider: "email",
		externalId: "victim@example.com",
		email: "victim@example.com",
		emailVerified: true,
	},
];

const describe = (response: unknown): string => {
	return response === undefined ? "undefined" : JSON.stringify(response);
};

const looksLikeClaims = (value: unknown): boolean => {
	return (
		typeof value === "object" &&
		value !== null &&
		typeof Reflect.get(value, "provider") === "string" &&
		typeof Reflect.get(value, "externalId") === "string"
	);
};

const probe = async (
	factor: Factor,
	response: unknown,
): Promise<Finding | undefined> => {
	try {
		const outcome = await factor.verify(response, {
			tenant: "doctor",
			proofs: [],
		});

		if (outcome.ok && looksLikeClaims(outcome.value)) {
			return {
				id: "factor-accepts-empty-evidence",
				level: "error",
				title: `Factor "${factor.id}" proves claims from a response that proves nothing`,
				scenario: [
					`Send a sign-in request for factor "${factor.id}" with the response ${describe(response)}.`,
					`The factor answers with claims ${describe(outcome.value)} and the core takes them as proof.`,
					"The attacker is signed in as that identity without holding any secret.",
				],
				fix: "A factor must return claims only for evidence it checked itself: a signature, a one-time code, a token it can verify. Never copy claims from the response.",
			};
		}
	} catch {
		return undefined;
	}

	return undefined;
};

export const factorsCheck: Check = {
	id: "factor-accepts-empty-evidence",
	title: "Factors refuse a response that proves nothing",
	async run({ factors = [] }) {
		const findings: Finding[] = [];

		for (const factor of factors) {
			for (const response of NO_EVIDENCE) {
				const finding = await probe(factor, response);

				if (finding !== undefined) {
					findings.push(finding);
					break;
				}
			}
		}

		return findings;
	},
};
