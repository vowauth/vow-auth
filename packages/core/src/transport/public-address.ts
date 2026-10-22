const IPV4_PARTS = 4;
const IPV6_GROUPS = 8;
const MAXIMUM_OCTET = 255;
const GROUP_RADIX = 16;
const OCTET_BITS = 8;
const MAPPED_GROUP = 0xffff;

type Ipv4Block = readonly [number, number, number, number];

const BLOCKED_IPV4: readonly Ipv4Block[] = [
	[0, 0, 0, 8],
	[10, 0, 0, 8],
	[100, 64, 0, 10],
	[127, 0, 0, 8],
	[169, 254, 0, 16],
	[172, 16, 0, 12],
	[192, 0, 0, 24],
	[192, 0, 2, 24],
	[192, 88, 99, 24],
	[192, 168, 0, 16],
	[198, 18, 0, 15],
	[198, 51, 100, 24],
	[203, 0, 113, 24],
	[224, 0, 0, 4],
	[240, 0, 0, 4],
];

const parseIpv4 = (text: string): readonly number[] | undefined => {
	const parts = text.split(".");

	if (parts.length !== IPV4_PARTS) {
		return undefined;
	}

	const octets = parts.map((part) =>
		/^(0|[1-9]\d{0,2})$/.test(part) ? Number(part) : Number.NaN,
	);

	return octets.every((octet) => octet <= MAXIMUM_OCTET) ? octets : undefined;
};

const toGroups = (side: string): number[] | undefined => {
	if (side === "") {
		return [];
	}

	const groups = side
		.split(":")
		.map((piece) =>
			/^[0-9a-f]{1,4}$/i.test(piece)
				? Number.parseInt(piece, GROUP_RADIX)
				: Number.NaN,
		);

	return groups.every((group) => !Number.isNaN(group)) ? groups : undefined;
};

const groupsOfIpv4 = (octets: readonly number[]): number[] => [
	((octets[0] ?? 0) << OCTET_BITS) | (octets[1] ?? 0),
	((octets[2] ?? 0) << OCTET_BITS) | (octets[3] ?? 0),
];

const parseIpv6 = (text: string): readonly number[] | undefined => {
	let body = text;
	let tail: number[] = [];

	if (text.includes(".")) {
		const lastColon = text.lastIndexOf(":");
		const embedded = parseIpv4(text.slice(lastColon + 1));

		if (embedded === undefined) {
			return undefined;
		}

		const prefix = text.slice(0, lastColon + 1);

		tail = groupsOfIpv4(embedded);
		body = prefix.endsWith("::") ? prefix : prefix.slice(0, -1);
	}

	const halves = body.split("::");

	if (halves.length > 2) {
		return undefined;
	}

	const before = toGroups(halves[0] ?? "");
	const after = halves.length === 2 ? toGroups(halves[1] ?? "") : [];

	if (before === undefined || after === undefined) {
		return undefined;
	}

	if (halves.length === 1) {
		const whole = [...before, ...tail];

		return whole.length === IPV6_GROUPS ? whole : undefined;
	}

	const missing = IPV6_GROUPS - before.length - after.length - tail.length;

	return missing >= 1
		? [...before, ...new Array<number>(missing).fill(0), ...after, ...tail]
		: undefined;
};

const inIpv4Block = (octets: readonly number[], block: Ipv4Block): boolean => {
	const [first, second, third, prefix] = block;
	const base = [first, second, third, 0];
	let remaining = prefix;

	for (let index = 0; index < IPV4_PARTS; index += 1) {
		const bits = Math.min(OCTET_BITS, remaining);
		const mask = (MAXIMUM_OCTET << (OCTET_BITS - bits)) & MAXIMUM_OCTET;

		if (((octets[index] ?? 0) & mask) !== ((base[index] ?? 0) & mask)) {
			return false;
		}

		remaining -= bits;
	}

	return true;
};

const isPublicIpv4 = (octets: readonly number[]): boolean => {
	return !BLOCKED_IPV4.some((block) => inIpv4Block(octets, block));
};

const octetsOfGroups = (high: number, low: number): readonly number[] => [
	high >> OCTET_BITS,
	high & MAXIMUM_OCTET,
	low >> OCTET_BITS,
	low & MAXIMUM_OCTET,
];

const isPublicIpv6 = (groups: readonly number[]): boolean => {
	const [first = 0, second = 0, third = 0, fourth = 0] = groups;
	const [fifth = 0, sixth = 0, seventh = 0, eighth = 0] = groups.slice(4);
	const leadingZeros = groups.slice(0, 5).every((group) => group === 0);

	if (leadingZeros && sixth === MAPPED_GROUP) {
		return isPublicIpv4(octetsOfGroups(seventh, eighth));
	}

	const isNat64 =
		first === 0x64 &&
		second === 0xff9b &&
		third === 0 &&
		fourth === 0 &&
		fifth === 0 &&
		sixth === 0;

	if (isNat64) {
		return isPublicIpv4(octetsOfGroups(seventh, eighth));
	}

	if (first === 0x2002) {
		return isPublicIpv4(octetsOfGroups(second, third));
	}

	const isGlobalUnicast = (first & 0xe000) === 0x2000;
	const isSpecialPurpose =
		(first === 0x2001 && second < 0x200) ||
		(first === 0x2001 && second === 0xdb8) ||
		(first === 0x3fff && second < 0x1000);

	return isGlobalUnicast && !isSpecialPurpose;
};

/**
 * Whether the text is an IP address that anyone on the internet could be
 * reached at. It is `false` for private, loopback, link-local, shared,
 * documentation, multicast and reserved ranges, for IPv4 hidden in IPv6
 * (mapped, NAT64, 6to4) when the IPv4 is one of those, and for anything that
 * is not a plain address, so a hex, octal or shortened IPv4 never passes. An
 * IPv6 address may be given with or without brackets.
 */
export function isPublicAddress(text: string): boolean {
	const unbracketed =
		text.startsWith("[") && text.endsWith("]") ? text.slice(1, -1) : text;
	const ipv4 = parseIpv4(unbracketed);

	if (ipv4 !== undefined) {
		return isPublicIpv4(ipv4);
	}

	const ipv6 = unbracketed.includes(":") ? parseIpv6(unbracketed) : undefined;

	return ipv6 !== undefined && isPublicIpv6(ipv6);
}
