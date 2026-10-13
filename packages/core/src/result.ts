/** Outcome of an operation that can fail on untrusted input without throwing. */
export type Result<Value, Failure = string> =
	| { readonly ok: true; readonly value: Value }
	| { readonly ok: false; readonly error: Failure };

/** Wraps a value into a successful {@link Result}. */
export const succeed = <Value>(value: Value): Result<Value, never> => ({
	ok: true,
	value,
});

/** Wraps an error into a failed {@link Result}. */
export const fail = <Failure>(error: Failure): Result<never, Failure> => ({
	ok: false,
	error,
});
