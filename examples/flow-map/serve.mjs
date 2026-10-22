import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 4173);
const TYPES = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
};

createServer((request, response) => {
	const requested = new URL(request.url ?? "/", "http://localhost").pathname;
	const path = normalize(
		join(HERE, requested === "/" ? "index.html" : requested),
	);
	const servable =
		path.startsWith(HERE) &&
		extname(path) in TYPES &&
		existsSync(path) &&
		statSync(path).isFile();

	if (!servable) {
		response.writeHead(404).end("Not found");

		return;
	}

	response.writeHead(200, { "content-type": TYPES[extname(path)] });
	createReadStream(path).pipe(response);
}).listen(PORT, () => {
	console.log(`Карта путей: http://localhost:${PORT}`);
});
