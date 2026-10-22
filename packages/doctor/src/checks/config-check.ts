import { createAuth } from "@vow-auth/core";
import type { Check } from "../finding.js";

export const configCheck: Check = {
	id: "config-refused",
	title: "The core accepts the options",
	async run({ options }) {
		try {
			createAuth(options);

			return [];
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);

			return [
				{
					id: "config-refused",
					level: "error",
					title: "The core refuses these options",
					scenario: [
						`The application cannot start: createAuth throws "${message}".`,
					],
					fix: "Change the option that the message names; the core checks it on purpose.",
				},
			];
		}
	},
};
