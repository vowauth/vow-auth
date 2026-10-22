import { once } from "node:events";
import { connect } from "node:net";

type Reply = string | number | null | Error | readonly Reply[];

const encodeCommand = (parts: readonly string[]): string => {
	return `*${parts.length}\r\n${parts
		.map((part) => `$${Buffer.byteLength(part)}\r\n${part}\r\n`)
		.join("")}`;
};

const parseReply = (
	buffer: Buffer,
	offset: number,
): readonly [Reply, number] | undefined => {
	const lineEnd = buffer.indexOf("\r\n", offset);

	if (lineEnd < 0) {
		return undefined;
	}

	const type = buffer.toString("latin1", offset, offset + 1);
	const line = buffer.toString("utf8", offset + 1, lineEnd);
	const next = lineEnd + 2;

	if (type === "+") {
		return [line, next];
	}

	if (type === "-") {
		return [new Error(line), next];
	}

	if (type === ":") {
		return [Number(line), next];
	}

	const length = Number(line);

	if (length < 0) {
		return [null, next];
	}

	if (type === "$") {
		return buffer.length < next + length + 2
			? undefined
			: [buffer.toString("utf8", next, next + length), next + length + 2];
	}

	const items: Reply[] = [];
	let cursor = next;

	for (let index = 0; index < length; index += 1) {
		const parsed = parseReply(buffer, cursor);

		if (parsed === undefined) {
			return undefined;
		}

		items.push(parsed[0]);
		cursor = parsed[1];
	}

	return [items, cursor];
};

export const createConnection = async (url: string) => {
	const { hostname, port } = new URL(url);
	const socket = connect(Number(port), hostname);
	const waiting: {
		readonly resolve: (reply: Reply) => void;
		readonly reject: (error: Error) => void;
	}[] = [];
	let buffer = Buffer.alloc(0);

	socket.on("data", (chunk: Buffer) => {
		buffer = Buffer.concat([buffer, chunk]);

		for (
			let parsed = parseReply(buffer, 0);
			parsed !== undefined;
			parsed = parseReply(buffer, 0)
		) {
			buffer = buffer.subarray(parsed[1]);
			const waiter = waiting.shift();

			if (parsed[0] instanceof Error) {
				waiter?.reject(parsed[0]);
			} else {
				waiter?.resolve(parsed[0]);
			}
		}
	});
	await once(socket, "connect");

	return {
		command: (...parts: string[]): Promise<Reply> => {
			return new Promise((resolve, reject) => {
				waiting.push({ resolve, reject });
				socket.write(encodeCommand(parts));
			});
		},
		close: () => {
			socket.end();
		},
	};
};

export const sleep = (milliseconds: number) => {
	return new Promise((resolve) => setTimeout(resolve, milliseconds));
};
