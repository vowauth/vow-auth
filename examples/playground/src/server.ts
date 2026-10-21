import { createServer } from "node:http";
import { createPlayground } from "./app.js";

const port = Number(process.env.PORT ?? 3000);
const WORKER_INTERVAL_MILLISECONDS = 250;
const playground = await createPlayground();

setInterval(() => {
	void playground.runWorker();
}, WORKER_INTERVAL_MILLISECONDS);

createServer(async (incoming, outgoing) => {
	const chunks: Buffer[] = [];

	for await (const chunk of incoming) {
		chunks.push(chunk);
	}

	const headers = new Headers();

	for (const [name, value] of Object.entries(incoming.headers)) {
		if (typeof value === "string") {
			headers.set(name, value);
		}
	}

	const method = incoming.method ?? "GET";
	const hasBody = method !== "GET" && method !== "HEAD";
	const response = await playground.handle(
		new Request(`http://localhost:${port}${incoming.url ?? "/"}`, {
			method,
			headers,
			body: hasBody ? Buffer.concat(chunks) : null,
		}),
	);

	outgoing.writeHead(response.status, Object.fromEntries(response.headers));
	outgoing.end(Buffer.from(await response.arrayBuffer()));
}).listen(port, () => {
	console.log(`Vow Auth playground: http://localhost:${port}`);
});
