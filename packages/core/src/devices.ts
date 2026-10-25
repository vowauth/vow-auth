import { defineDuration } from "./duration.js";
import type { Sealer } from "./sealer.js";
import { generateSecret } from "./shared/secret.js";

const DEVICE_PURPOSE = "device";
const DEVICE_ID = /^[0-9a-f]{64}$/;

/** A new device: the id that sessions record, and the handle the client keeps. */
export type IssuedDevice = {
	readonly id: string;
	readonly handle: string;
};

/**
 * Devices the engine hands out. The id is random and never chosen by a
 * client, so signing out of one device ends that device and no other; the
 * handle is the id sealed by the engine, so a client cannot claim the device
 * of someone else.
 */
export type Devices = {
	issue(): Promise<IssuedDevice>;
	/** The id inside a handle the engine issued; `undefined` for anything else. */
	open(handle: string): Promise<string | undefined>;
};

/** Creates the devices of the engine, sealed with the core's own sealer. */
export function createDevices(options: {
	readonly sealer: Sealer;
	readonly timeToLiveMilliseconds: number;
}): Devices {
	const timeToLive = defineDuration(options.timeToLiveMilliseconds);

	if (!timeToLive.ok) {
		throw new RangeError(
			"the life time of a device must be a positive finite number",
		);
	}

	return {
		async issue() {
			const id = generateSecret();
			const handle = await options.sealer.seal({
				purpose: DEVICE_PURPOSE,
				payload: { id },
				timeToLive: timeToLive.value,
			});

			return { id, handle };
		},
		async open(handle) {
			const opened = await options.sealer.unseal(handle, DEVICE_PURPOSE);

			if (!opened.ok) {
				return undefined;
			}

			const id = Object.hasOwn(opened.value, "id")
				? opened.value.id
				: undefined;

			return id !== undefined && DEVICE_ID.test(id) ? id : undefined;
		},
	};
}
