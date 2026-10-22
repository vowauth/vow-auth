import type { Check, Finding } from "../finding.js";

const MINIMUM_DISTINCT_CHARACTERS = 9;
const PLACEHOLDERS = [
	"changeme",
	"password",
	"secret",
	"example",
	"qwerty",
	"12345678",
	"letmein",
];

const repeatsShortPattern = (text: string): boolean => {
	for (let period = 1; period <= text.length / 2; period += 1) {
		const unit = text.slice(0, period);

		if (unit.repeat(Math.ceil(text.length / period)).startsWith(text)) {
			return true;
		}
	}

	return false;
};

const weaknessOf = (value: string): string | undefined => {
	if (new Set(value).size < MINIMUM_DISTINCT_CHARACTERS) {
		return `it uses only ${new Set(value).size} different characters`;
	}

	if (repeatsShortPattern(value)) {
		return "it is a short pattern repeated";
	}

	const lower = value.toLowerCase();
	const placeholder = PLACEHOLDERS.find((word) => lower.includes(word));

	return placeholder === undefined
		? undefined
		: `it contains the placeholder "${placeholder}"`;
};

export const secretsCheck: Check = {
	id: "secrets-low-entropy",
	title: "Secrets look random",
	async run({ options }) {
		const findings: Finding[] = [];

		for (const { version, value } of options.secrets) {
			const weakness = weaknessOf(value);

			if (weakness !== undefined) {
				findings.push({
					id: "secrets-low-entropy",
					level: "error",
					title: `Secret version ${version} is guessable: ${weakness}`,
					scenario: [
						`Guess secret version ${version}; ${weakness}.`,
						"Seal a session token for any subject with it.",
						"Send that token to the application: it verifies, and the attacker is signed in as that subject.",
					],
					fix: "Generate the secret from a secure random source, for example `openssl rand -base64 32`, keep it out of the repository, and rotate by adding the new version first.",
				});
			}
		}

		return findings;
	},
};
