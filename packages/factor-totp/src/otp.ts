export const DIGITS = 6;
export const PERIOD_SECONDS = 30;
const WINDOW_STEPS = 1;
export const SECRET_BYTES = 20;

const COUNTER_BYTES = 8;
const MODULUS = 10 ** DIGITS;
const CODE_PATTERN = new RegExp(`^[0-9]{${DIGITS}}$`);
const MILLISECONDS_PER_SECOND = 1_000;
const LOW_NIBBLE = 0x0f;
const POSITIVE_INT31 = 0x7fffffff;

const importKey = (secret: Uint8Array<ArrayBuffer>) =>
	crypto.subtle.importKey(
		"raw",
		secret,
		{ name: "HMAC", hash: "SHA-1" },
		false,
		["sign"],
	);

/** The time step a moment falls in: RFC 6238 counts steps of 30 seconds from the Unix epoch. */
export const stepOf = (nowMilliseconds: number): number => {
	return Math.floor(nowMilliseconds / MILLISECONDS_PER_SECOND / PERIOD_SECONDS);
};

/** The code of one time step: HMAC-SHA-1 of the step counter, cut to six digits as RFC 4226 section 5.3 describes. */
export const generateCode = async (
	secret: Uint8Array<ArrayBuffer>,
	step: number,
): Promise<string> => {
	const counter = new DataView(new ArrayBuffer(COUNTER_BYTES));

	counter.setBigUint64(0, BigInt(step));

	const digest = new Uint8Array(
		await crypto.subtle.sign("HMAC", await importKey(secret), counter),
	);
	const offset = (digest[digest.length - 1] ?? 0) & LOW_NIBBLE;
	const view = new DataView(
		digest.buffer,
		digest.byteOffset,
		digest.byteLength,
	);
	const truncated = view.getUint32(offset) & POSITIVE_INT31;

	return String(truncated % MODULUS).padStart(DIGITS, "0");
};

const sameText = (left: string, right: string): boolean => {
	let difference = left.length ^ right.length;

	for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
		difference |=
			(left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
	}

	return difference === 0;
};

/**
 * The step whose code equals the one entered, looking at the current step and
 * at most one step either way (RFC 6238 section 5.2); `undefined` when none
 * does. Every step in the window is computed and compared the same way, so the
 * time taken does not say which one was close.
 */
export const findStep = async (
	secret: Uint8Array<ArrayBuffer>,
	code: string,
	nowMilliseconds: number,
): Promise<number | undefined> => {
	if (!CODE_PATTERN.test(code)) {
		return undefined;
	}

	const current = stepOf(nowMilliseconds);
	let found: number | undefined;

	for (let offset = -WINDOW_STEPS; offset <= WINDOW_STEPS; offset += 1) {
		const step = current + offset;

		if (step >= 0 && sameText(await generateCode(secret, step), code)) {
			found = step;
		}
	}

	return found;
};
