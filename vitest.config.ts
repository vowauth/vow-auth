import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		alias: {
			"@vow-auth/core": fileURLToPath(
				new URL("./packages/core/src/index.ts", import.meta.url),
			),
			"@vow-auth/adapter-memory": fileURLToPath(
				new URL("./packages/adapter-memory/src/index.ts", import.meta.url),
			),
			"@vow-auth/factor-email-link": fileURLToPath(
				new URL("./packages/factor-email-link/src/index.ts", import.meta.url),
			),
			"@vow-auth/adapter-redis": fileURLToPath(
				new URL("./packages/adapter-redis/src/index.ts", import.meta.url),
			),
		},
	},
	test: {
		include: ["packages/*/tests/**/*.test.ts", "examples/*/tests/**/*.test.ts"],
	},
});
