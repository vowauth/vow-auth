// ruleid: runs-anywhere
import { readFileSync } from "node:fs";
// ruleid: runs-anywhere
import * as path from "node:path";
import { createAuth } from "@vow-auth/core";
// ruleid: no-internal-entry
import { createLimiter } from "@vow-auth/core/internal";
// ruleid: no-internal-entry
import { createSealer } from "../packages/core/src/internal.js";

declare const value: string;
declare const secret: string;
declare const expectedMac: string;
declare const key: Uint8Array<ArrayBuffer>;
declare const run: (statement: string, parameters: unknown[]) => unknown;

export const imports = [readFileSync, path, createAuth, createLimiter, createSealer];

export const randomness = () => {
	// ruleid: no-math-random
	const weak = Math.random();
	// ok: no-math-random
	const strong = crypto.getRandomValues(new Uint8Array(16));

	return [weak, strong];
};

export const dynamicCode = () => {
	// ruleid: no-dynamic-code
	eval(value);
	// ruleid: no-dynamic-code
	new Function(value);
	// ok: no-dynamic-code
	setTimeout(() => value, 1);
};

export const keys = async () => {
	// ruleid: extractable-key
	await crypto.subtle.importKey("raw", key, "HKDF", true, ["deriveKey"]);
	// ok: extractable-key
	await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveKey"]);
	// ruleid: weak-hash
	await crypto.subtle.digest("SHA-1", key);
	// ok: weak-hash
	await crypto.subtle.digest("SHA-256", key);
};

export const compare = (mac: string) => {
	// ruleid: secret-compared-in-variable-time
	const same = expectedMac === mac;
	// ruleid: secret-compared-in-variable-time
	const different = secret !== value;
	// ok: secret-compared-in-variable-time
	const missing = secret === undefined;

	return [same, different, missing];
};

const SERVER_NOW = "now()";
const STATEMENTS = ["select 1"];
// ruleid: statement-built-from-values
const BUILT = `select * from t where id = '${value}'`;
// ok: statement-built-from-values
const CONSTANT = `select ${SERVER_NOW}`;
// ok: statement-built-from-values
const JOINED = `${STATEMENTS.join(";\n\n")};\n`;
// ok: statement-built-from-values
const message = `no such tenant: ${value}`;

export const statements = () => {
	// ruleid: statement-built-from-values
	run(`delete from t where id = '${value}'`, []);

	return [BUILT, CONSTANT, JOINED, message];
};
