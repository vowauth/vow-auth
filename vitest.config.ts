import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		alias: {
			"@vow-auth/core/internal": fileURLToPath(
				new URL("./packages/core/src/internal.ts", import.meta.url),
			),
			"@vow-auth/core": fileURLToPath(
				new URL("./packages/core/src/index.ts", import.meta.url),
			),
			"@vow-auth/adapter-memory": fileURLToPath(
				new URL("./packages/adapter-memory/src/index.ts", import.meta.url),
			),
			"@vow-auth/doctor": fileURLToPath(
				new URL("./packages/doctor/src/index.ts", import.meta.url),
			),
			"@vow-auth/adapter-postgres": fileURLToPath(
				new URL("./packages/adapter-postgres/src/index.ts", import.meta.url),
			),
			"@vow-auth/http": fileURLToPath(
				new URL("./packages/http/src/index.ts", import.meta.url),
			),
			"@vow-auth/service": fileURLToPath(
				new URL("./packages/service/src/index.ts", import.meta.url),
			),
			"@vow-auth/test-support": fileURLToPath(
				new URL("./packages/test-support/src/index.ts", import.meta.url),
			),
			"@vow-auth/store-contracts": fileURLToPath(
				new URL("./packages/store-contracts/src/index.ts", import.meta.url),
			),
			"@vow-auth/authorize": fileURLToPath(
				new URL("./packages/authorize/src/index.ts", import.meta.url),
			),
			"@vow-auth/factor-email-link": fileURLToPath(
				new URL("./packages/factor-email-link/src/index.ts", import.meta.url),
			),
			"@vow-auth/factor-totp": fileURLToPath(
				new URL("./packages/factor-totp/src/index.ts", import.meta.url),
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
