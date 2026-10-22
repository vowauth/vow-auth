(() => {
	const data = window.FLOW_DATA;
	const SVG_NS = "http://www.w3.org/2000/svg";
	const NODE_WIDTH = 236;
	const GAP_X = 34;
	const GAP_Y = 78;
	const MARGIN = 28;
	const LINE_HEIGHT = 16;
	const TITLE_COLUMNS = 25;
	const FUNCTION_COLUMNS = 28;
	const PATH_LIMIT = 400;
	const flowsById = new Map(data.flows.map((flow) => [flow.id, flow]));

	const KIND_LABELS = {
		start: "Вход",
		step: "Шаг",
		decision: "Развилка",
		port: "Обращение к хранилищу",
		adapter: "Адаптер",
		"end-ok": "Успех",
		"end-fail": "Отказ",
		"end-wait": "Нужен ещё шаг",
		jump: "Переход в другой путь",
	};
	const GLYPHS = {
		start: "▶",
		step: "",
		decision: "◇",
		port: "▤",
		adapter: "▣",
		"end-ok": "✓",
		"end-fail": "✕",
		"end-wait": "…",
		jump: "↗",
	};
	const SPECIAL_PAGES = {
		audit: "Журнал аудита",
		ports: "Порты и адаптеры",
	};

	const state = {
		view: "flow",
		flowId: data.flows[0].id,
		nodeId: undefined,
		pathIndex: undefined,
		zoom: 1,
		query: "",
		root: "",
	};

	const byId = (id) => document.getElementById(id);

	const html = (tag, properties = {}, ...children) => {
		const element = document.createElement(tag);

		for (const [name, value] of Object.entries(properties)) {
			if (name === "class") element.className = value;
			else if (name.startsWith("on"))
				element.addEventListener(name.slice(2), value);
			else if (value === true) element.setAttribute(name, "");
			else if (value !== false && value !== undefined)
				element.setAttribute(name, value);
		}

		for (const child of children.flat(Number.POSITIVE_INFINITY)) {
			if (child === undefined || child === null || child === false) continue;
			element.append(
				child instanceof Node ? child : document.createTextNode(String(child)),
			);
		}

		return element;
	};

	const svg = (tag, properties = {}, ...children) => {
		const element = document.createElementNS(SVG_NS, tag);

		for (const [name, value] of Object.entries(properties)) {
			if (value !== undefined && value !== false)
				element.setAttribute(name, String(value));
		}

		for (const child of children.flat(Number.POSITIVE_INFINITY)) {
			if (child === undefined || child === null) continue;
			element.append(
				child instanceof Node ? child : document.createTextNode(String(child)),
			);
		}

		return element;
	};

	const wrap = (text, columns, maximumLines) => {
		const lines = [];
		let line = "";

		const words = text
			.split(/\s+/)
			.flatMap(
				(word) => word.match(new RegExp(`.{1,${columns}}`, "g")) ?? [word],
			);

		for (const word of words) {
			if (line !== "" && `${line} ${word}`.length > columns) {
				lines.push(line);
				line = word;
			} else {
				line = line === "" ? word : `${line} ${word}`;
			}
		}

		if (line !== "") lines.push(line);

		if (lines.length > maximumLines) {
			const kept = lines.slice(0, maximumLines);

			kept[maximumLines - 1] =
				`${kept[maximumLines - 1].slice(0, columns - 1)}…`;

			return kept;
		}

		return lines;
	};

	const truncate = (text, columns) =>
		text.length > columns ? `${text.slice(0, columns - 1)}…` : text;

	const components = (flow) => {
		const parent = new Map(flow.nodes.map((node) => [node.id, node.id]));
		const find = (id) => {
			let root = id;

			while (parent.get(root) !== root) root = parent.get(root);

			parent.set(id, root);

			return root;
		};

		for (const edge of flow.edges) parent.set(find(edge.from), find(edge.to));

		const groups = new Map();

		for (const node of flow.nodes) {
			const root = find(node.id);

			groups.set(root, [...(groups.get(root) ?? []), node]);
		}

		return [...groups.values()].map((nodes) => {
			const ids = new Set(nodes.map((node) => node.id));

			return {
				nodes,
				edges: flow.edges
					.map((edge, index) => ({ ...edge, originalIndex: index }))
					.filter((edge) => ids.has(edge.from)),
			};
		});
	};

	const layoutFlow = (flow) => {
		const items = new Map();
		const edges = [];
		let offset = 0;
		let width = 0;

		for (const part of components(flow)) {
			const laidOut = layoutComponent(part, offset);

			for (const [id, item] of laidOut.items) items.set(id, item);

			edges.push(...laidOut.edges);
			width = Math.max(width, laidOut.width);
			offset += laidOut.height;
		}

		return { items, edges, width, height: offset };
	};

	const layoutComponent = (flow, offsetY) => {
		const parentsOf = new Map(flow.nodes.map((node) => [node.id, []]));

		for (const edge of flow.edges) parentsOf.get(edge.to).push(edge.from);

		const layerOf = new Map();
		const layerFor = (id) => {
			if (layerOf.has(id)) return layerOf.get(id);
			const explicit = flow.nodes.find((node) => node.id === id).layer;

			if (explicit !== undefined) {
				layerOf.set(id, explicit);

				return explicit;
			}

			layerOf.set(id, 0);

			const parents = parentsOf.get(id);
			const layer =
				parents.length === 0 ? 0 : 1 + Math.max(...parents.map(layerFor));

			layerOf.set(id, layer);

			return layer;
		};

		for (const node of flow.nodes) layerFor(node.id);

		const items = new Map();

		flow.nodes.forEach((node, order) => {
			const titleLines = wrap(node.title, TITLE_COLUMNS, 3);
			const functionLine =
				node.fn === undefined ? undefined : truncate(node.fn, FUNCTION_COLUMNS);

			items.set(node.id, {
				id: node.id,
				node,
				order,
				layer: layerOf.get(node.id),
				titleLines,
				functionLine,
				width: NODE_WIDTH,
				height:
					16 +
					titleLines.length * LINE_HEIGHT +
					(functionLine === undefined ? 0 : LINE_HEIGHT),
				parents: [],
				children: [],
			});
		});

		const chains = flow.edges.map((edge, index) => {
			const from = layerOf.get(edge.from);
			const to = layerOf.get(edge.to);
			const ids = [edge.from];

			for (let layer = from + 1; layer < to; layer += 1) {
				const id = `~${index}:${layer}`;

				items.set(id, {
					id,
					dummy: true,
					order: items.get(edge.from).order + 0.5,
					layer,
					width: 8,
					height: 8,
					parents: [],
					children: [],
				});
				ids.push(id);
			}

			ids.push(edge.to);

			for (let position = 0; position + 1 < ids.length; position += 1) {
				items.get(ids[position]).children.push(items.get(ids[position + 1]));
				items.get(ids[position + 1]).parents.push(items.get(ids[position]));
			}

			return { edge, index, ids };
		});

		const layerCount =
			1 + Math.max(...[...items.values()].map((item) => item.layer));
		const layers = Array.from({ length: layerCount }, () => []);

		for (const item of items.values()) layers[item.layer].push(item);
		for (const layer of layers)
			layer.sort((left, right) => left.order - right.order);

		const reorder = (layer, neighbours) => {
			const keyed = layer.map((item, index) => {
				const related = neighbours(item);
				const key =
					related.length === 0
						? index
						: related.reduce(
								(sum, other) => sum + layers[other.layer].indexOf(other),
								0,
							) / related.length;

				return { item, key, index };
			});

			keyed.sort(
				(left, right) => left.key - right.key || left.index - right.index,
			);
			layer.splice(0, layer.length, ...keyed.map((entry) => entry.item));
		};

		for (let sweep = 0; sweep < 6; sweep += 1) {
			for (let index = 1; index < layerCount; index += 1)
				reorder(layers[index], (item) => item.parents);
			for (let index = layerCount - 2; index >= 0; index -= 1)
				reorder(layers[index], (item) => item.children);
		}

		const place = (layer, desired) => {
			let right = -Infinity;

			for (const item of layer) {
				const wanted = desired(item) ?? item.x;
				const least =
					right === -Infinity ? -Infinity : right + GAP_X + item.width / 2;

				item.x = Math.max(wanted, least);
				right = item.x + item.width / 2;
			}
		};

		for (const layer of layers) {
			let cursor = 0;

			for (const item of layer) {
				item.x = cursor + item.width / 2;
				cursor += item.width + GAP_X;
			}
		}

		const widest = Math.max(
			...layers.map((layer) =>
				layer.reduce((sum, item) => sum + item.width + GAP_X, -GAP_X),
			),
		);

		for (const layer of layers) {
			const width = layer.reduce(
				(sum, item) => sum + item.width + GAP_X,
				-GAP_X,
			);
			const shift = (widest - width) / 2;

			for (const item of layer) item.x += shift;
		}

		const mean = (related) =>
			related.length === 0
				? undefined
				: related.reduce((sum, other) => sum + other.x, 0) / related.length;

		for (let sweep = 0; sweep < 8; sweep += 1) {
			for (let index = 1; index < layerCount; index += 1)
				place(layers[index], (item) => mean(item.parents));
			for (let index = layerCount - 2; index >= 0; index -= 1)
				place(layers[index], (item) => mean(item.children));
		}

		const left = Math.min(
			...[...items.values()].map((item) => item.x - item.width / 2),
		);

		for (const item of items.values()) item.x += MARGIN - left;

		let top = MARGIN + offsetY;

		for (const layer of layers) {
			const height = Math.max(...layer.map((item) => item.height));

			for (const item of layer) item.y = top + (height - item.height) / 2;

			top += height + GAP_Y;
		}

		const outgoing = new Map();
		const incoming = new Map();

		for (const chain of chains) {
			const first = items.get(chain.ids[1]);
			const last = items.get(chain.ids[chain.ids.length - 2]);

			(
				outgoing.get(chain.edge.from) ??
				outgoing.set(chain.edge.from, []).get(chain.edge.from)
			).push({ chain, other: first });
			(
				incoming.get(chain.edge.to) ??
				incoming.set(chain.edge.to, []).get(chain.edge.to)
			).push({ chain, other: last });
		}

		const offsets = new Map();
		const spread = (groups, side) => {
			for (const [id, entries] of groups) {
				entries.sort((a, b) => a.other.x - b.other.x);

				const width = items.get(id).width - 36;
				const step =
					entries.length > 1 ? Math.min(26, width / (entries.length - 1)) : 0;

				entries.forEach((entry, index) => {
					offsets.set(
						`${side}:${entry.chain.index}`,
						(index - (entries.length - 1) / 2) * step,
					);
				});
			}
		};

		spread(outgoing, "out");
		spread(incoming, "in");

		const edges = chains.map((chain) => {
			const points = chain.ids.map((id, position) => {
				const item = items.get(id);

				if (position === 0)
					return {
						x: item.x + offsets.get(`out:${chain.index}`),
						y: item.y + item.height,
					};
				if (position === chain.ids.length - 1)
					return { x: item.x + offsets.get(`in:${chain.index}`), y: item.y };

				return { x: item.x, y: item.y + item.height / 2 };
			});
			let path = `M ${points[0].x} ${points[0].y}`;

			for (let index = 1; index < points.length; index += 1) {
				const from = points[index - 1];
				const to = points[index];
				const half = Math.max(18, (to.y - from.y) / 2);

				path += ` C ${from.x} ${from.y + half}, ${to.x} ${to.y - half}, ${to.x} ${to.y}`;
			}

			const from = points[0];
			const to = points[1];
			const half = Math.max(18, (to.y - from.y) / 2);
			const t = 0.42;
			const mix = (a, b, c, d) =>
				(1 - t) ** 3 * a +
				3 * (1 - t) ** 2 * t * b +
				3 * (1 - t) * t ** 2 * c +
				t ** 3 * d;

			return {
				...chain.edge,
				index: chain.edge.originalIndex ?? chain.index,
				path,
				labelX: mix(from.x, from.x, to.x, to.x),
				labelY: mix(from.y, from.y + half, to.y - half, to.y),
			};
		});

		return {
			items,
			edges,
			width:
				Math.max(
					...[...items.values()].map((item) => item.x + item.width / 2),
				) + MARGIN,
			height: top - GAP_Y + MARGIN - offsetY,
		};
	};

	const enumeratePaths = (flow) => {
		const outgoing = new Map(flow.nodes.map((node) => [node.id, []]));

		for (const [index, edge] of flow.edges.entries()) {
			outgoing.get(edge.from).push({ edge, index });
		}

		const nodes = new Map(flow.nodes.map((node) => [node.id, node]));
		const paths = [];
		const walk = (id, visitedNodes, visitedEdges) => {
			if (paths.length >= PATH_LIMIT) return;

			const node = nodes.get(id);
			const nextNodes = [...visitedNodes, id];

			if (
				node.kind.startsWith("end") ||
				(outgoing.get(id).length === 0 && node.kind !== "start")
			) {
				paths.push({ nodes: nextNodes, edges: visitedEdges });

				return;
			}

			for (const { edge, index } of outgoing.get(id))
				walk(edge.to, nextNodes, [...visitedEdges, index]);
		};

		for (const node of flow.nodes) {
			if (node.kind === "start") walk(node.id, [], []);
		}

		return paths;
	};

	const OUTCOME_ORDER = { "end-ok": 0, "end-wait": 1, jump: 2, "end-fail": 3 };

	const currentFlow = () => flowsById.get(state.flowId);

	const related = (flow, nodeId) => {
		const ancestors = new Set([nodeId]);
		const descendants = new Set([nodeId]);
		let grew = true;

		while (grew) {
			grew = false;

			for (const edge of flow.edges) {
				if (ancestors.has(edge.to) && !ancestors.has(edge.from)) {
					ancestors.add(edge.from);
					grew = true;
				}

				if (descendants.has(edge.from) && !descendants.has(edge.to)) {
					descendants.add(edge.to);
					grew = true;
				}
			}
		}

		return { ancestors, descendants };
	};

	const renderLegend = () => {
		const legend = byId("legend");

		legend.replaceChildren(
			...Object.entries(KIND_LABELS).map(([kind, label]) => {
				const swatch = html("span", { class: "swatch" });

				swatch.style.color = {
					start: "var(--accent)",
					step: "var(--line)",
					decision: "var(--wait)",
					port: "var(--port)",
					adapter: "var(--adapter)",
					"end-ok": "var(--ok)",
					"end-fail": "var(--fail)",
					"end-wait": "var(--wait)",
					jump: "var(--accent)",
				}[kind];

				return html("span", {}, swatch, label);
			}),
			html(
				"span",
				{},
				"Красная линия: отказ. Жёлтая: ответ развилки. Серая: обычный ход.",
			),
		);
	};

	const renderNav = () => {
		const nav = byId("nav");
		const children = [];

		if (state.query.trim().length >= 2) {
			const query = state.query.trim().toLowerCase();
			const hits = [];

			for (const flow of data.flows) {
				for (const node of flow.nodes) {
					const haystack = [
						node.title,
						node.fn,
						node.text,
						node.input,
						node.output,
						node.port,
						node.audit,
						node.source?.file,
						...(node.codes ?? []),
					]
						.filter(Boolean)
						.join(" ")
						.toLowerCase();

					if (haystack.includes(query)) hits.push({ flow, node });
				}
			}

			children.push(
				html(
					"div",
					{ class: "results" },
					html("h2", {}, `Найдено: ${hits.length}`),
					...hits
						.slice(0, 40)
						.map(({ flow, node }) =>
							html(
								"button",
								{ type: "button", onclick: () => openNode(flow.id, node.id) },
								node.title,
								html(
									"small",
									{},
									`${flow.title}${node.fn ? ` · ${node.fn}` : ""}`,
								),
							),
						),
				),
			);
		}

		for (const group of data.groups) {
			const flows = data.flows.filter((flow) => flow.group === group);

			if (flows.length === 0) continue;

			children.push(
				html("h2", {}, group),
				...flows.map((flow) =>
					html(
						"button",
						{
							type: "button",
							"aria-current":
								state.view === "flow" && state.flowId === flow.id
									? "page"
									: undefined,
							onclick: () => openFlow(flow.id),
						},
						flow.title,
					),
				),
			);
		}

		children.push(
			html("h2", {}, "Справочники"),
			...Object.entries(SPECIAL_PAGES).map(([id, title]) =>
				html(
					"button",
					{
						type: "button",
						"aria-current": state.view === id ? "page" : undefined,
						onclick: () => openSpecial(id),
					},
					title,
				),
			),
		);

		nav.replaceChildren(...children);
	};

	const renderDiagram = () => {
		const flow = currentFlow();
		const canvas = byId("canvas");
		const layout = layoutFlow(flow);
		const path =
			state.pathIndex === undefined
				? undefined
				: pathsOf(flow)[state.pathIndex];
		const chosen =
			state.nodeId === undefined ? undefined : related(flow, state.nodeId);
		const onPathNodes = path === undefined ? undefined : new Set(path.nodes);
		const onPathEdges = path === undefined ? undefined : new Set(path.edges);
		const graphic = svg(
			"svg",
			{
				width: layout.width * state.zoom,
				height: layout.height * state.zoom,
				viewBox: `0 0 ${layout.width} ${layout.height}`,
				role: "img",
				"aria-label": flow.title,
			},
			svg(
				"defs",
				{},
				...["ok", "fail", "branch"].map((kind) =>
					svg(
						"marker",
						{
							id: `arrow-${kind}`,
							viewBox: "0 0 10 10",
							refX: 9,
							refY: 5,
							markerWidth: 9,
							markerHeight: 9,
							orient: "auto",
							markerUnits: "userSpaceOnUse",
						},
						svg("path", { d: "M 0 0 L 10 5 L 0 10 z", class: `arrow-${kind}` }),
					),
				),
			),
		);
		const edgeLayer = svg("g");
		const nodeLayer = svg("g");
		const labelLayer = svg("g");

		for (const edge of layout.edges) {
			let dimmed = false;
			let hot = false;

			if (onPathEdges !== undefined) {
				dimmed = !onPathEdges.has(edge.index);
				hot = !dimmed;
			} else if (chosen !== undefined) {
				const upstream =
					chosen.ancestors.has(edge.from) && chosen.ancestors.has(edge.to);
				const downstream =
					chosen.descendants.has(edge.from) && chosen.descendants.has(edge.to);

				dimmed = !(upstream || downstream);
				hot = !dimmed;
			}

			const classes = `edge ${edge.kind}${dimmed ? " dim" : ""}${hot ? " hot" : ""}`;

			edgeLayer.append(
				svg("path", {
					d: edge.path,
					class: classes,
					"marker-end": `url(#arrow-${edge.kind})`,
				}),
			);

			if (edge.label !== "") {
				const width = edge.label.length * 6.3 + 10;
				const group = svg(
					"g",
					{ class: dimmed ? "dim" : "" },
					svg("rect", {
						class: "edge-label-box",
						x: edge.labelX - width / 2,
						y: edge.labelY - 9,
						width,
						height: 16,
						rx: 4,
					}),
					svg(
						"text",
						{
							class: "edge-label",
							x: edge.labelX,
							y: edge.labelY + 3,
							"text-anchor": "middle",
						},
						edge.label,
					),
				);

				labelLayer.append(group);
			}
		}

		for (const item of layout.items.values()) {
			if (item.dummy) continue;

			const node = item.node;
			let dimmed = false;

			if (onPathNodes !== undefined) {
				dimmed = !onPathNodes.has(node.id);
			} else if (chosen !== undefined) {
				dimmed = !(
					chosen.ancestors.has(node.id) || chosen.descendants.has(node.id)
				);
			}

			const group = svg(
				"g",
				{
					class: `node ${node.kind}${state.nodeId === node.id ? " selected" : ""}${dimmed ? " dim" : ""}`,
					tabindex: 0,
					role: "button",
					"aria-label": `${KIND_LABELS[node.kind]}: ${node.title}`,
					transform: `translate(${item.x - item.width / 2}, ${item.y})`,
				},
				svg("rect", {
					class: "card",
					width: item.width,
					height: item.height,
					rx:
						node.kind === "start" || node.kind.startsWith("end")
							? item.height / 2
							: 9,
				}),
				svg("text", { class: "glyph", x: 12, y: 22 }, GLYPHS[node.kind]),
				...item.titleLines.map((line, index) =>
					svg(
						"text",
						{
							x: GLYPHS[node.kind] === "" ? 14 : 30,
							y: 22 + index * LINE_HEIGHT,
						},
						line,
					),
				),
				item.functionLine === undefined
					? undefined
					: svg(
							"text",
							{
								class: "fn",
								x: GLYPHS[node.kind] === "" ? 14 : 30,
								y: 22 + item.titleLines.length * LINE_HEIGHT,
							},
							item.functionLine,
						),
			);

			group.addEventListener("click", () => selectNode(node.id));
			group.addEventListener("keydown", (event) => {
				if (event.key === "Enter" || event.key === " ") {
					event.preventDefault();
					selectNode(node.id);
				}
			});
			nodeLayer.append(group);
		}

		graphic.append(edgeLayer, nodeLayer, labelLayer);
		canvas.replaceChildren(graphic);
	};

	const pathsCache = new Map();

	const pathsOf = (flow) => {
		if (!pathsCache.has(flow.id)) {
			const nodes = new Map(flow.nodes.map((node) => [node.id, node]));
			const paths = enumeratePaths(flow);

			paths.sort((left, right) => {
				const rank = (path) =>
					OUTCOME_ORDER[nodes.get(path.nodes[path.nodes.length - 1]).kind] ?? 2;

				return (
					rank(left) - rank(right) || left.nodes.length - right.nodes.length
				);
			});
			pathsCache.set(flow.id, paths);
		}

		return pathsCache.get(flow.id);
	};

	const renderPaths = () => {
		const flow = currentFlow();
		const section = byId("paths");
		const paths = pathsOf(flow);
		const nodes = new Map(flow.nodes.map((node) => [node.id, node]));

		section.replaceChildren(
			html(
				"h2",
				{},
				`Все пути этого потока: ${paths.length}${paths.length >= PATH_LIMIT ? " (показаны первые)" : ""}`,
				" ",
				html(
					"span",
					{ class: "muted" },
					"Нажмите путь, чтобы подсветить его на схеме.",
				),
			),
			html(
				"ol",
				{},
				...paths.map((path, index) => {
					const last = nodes.get(path.nodes[path.nodes.length - 1]);
					const steps = path.nodes.map((id, position) => {
						const node = nodes.get(id);
						const edgeIndex = path.edges[position];
						const label =
							edgeIndex === undefined ? "" : flow.edges[edgeIndex].label;

						return [
							node.title,
							label === "" ? "" : html("em", {}, ` [${label}]`),
							position + 1 < path.nodes.length ? " → " : "",
						];
					});

					return html(
						"li",
						{},
						html(
							"button",
							{
								type: "button",
								"aria-pressed": state.pathIndex === index ? "true" : "false",
								onclick: () => {
									state.pathIndex =
										state.pathIndex === index ? undefined : index;
									state.nodeId = undefined;
									render();
								},
							},
							html("span", { class: `outcome ${last.kind}` }, last.title),
							html("span", { class: "sequence" }, steps),
						),
					);
				}),
			),
		);
	};

	const sourceLink = (source) => {
		const label = `${source.file}:${source.line}`;

		if (state.root === "") return html("code", {}, label);

		const root = state.root.replace(/\\/g, "/").replace(/\/$/, "");

		return html(
			"a",
			{ href: `vscode://file/${root}/${source.file}:${source.line}` },
			label,
		);
	};

	const section = (title, content) =>
		content === undefined || content === ""
			? undefined
			: [html("h3", {}, title), content];

	const renderDetails = () => {
		const details = byId("details");

		if (state.view !== "flow") {
			details.replaceChildren(
				html("h2", {}, SPECIAL_PAGES[state.view]),
				html(
					"p",
					{ class: "muted" },
					"Справочник собран из тех же данных, что и схемы. Нажмите строку, чтобы открыть узел на схеме.",
				),
			);

			return;
		}

		const flow = currentFlow();
		const node = flow.nodes.find((candidate) => candidate.id === state.nodeId);

		if (node === undefined) {
			details.replaceChildren(
				html("h2", {}, flow.title),
				html("p", {}, flow.summary),
				html(
					"p",
					{ class: "muted" },
					"Нажмите на узел схемы: здесь появится, какая функция что делает, что получает и отдаёт, куда пишет аудит и какие коды отказа возможны. Выбранный узел подсвечивает всё, что ведёт к нему и что идёт от него.",
				),
			);

			return;
		}

		const paths = pathsOf(flow);
		const reaching = paths.filter((path) =>
			path.nodes.includes(node.id),
		).length;

		details.replaceChildren(
			...[
				html("span", { class: "tag" }, KIND_LABELS[node.kind]),
				html("h2", {}, node.title),
				node.fn ? html("code", {}, node.fn) : undefined,
				section(
					"Что происходит",
					node.text ? html("p", {}, node.text) : undefined,
				),
				section(
					"Принимает",
					node.input ? html("p", {}, html("code", {}, node.input)) : undefined,
				),
				section(
					"Отдаёт",
					node.output
						? html("p", {}, html("code", {}, node.output))
						: undefined,
				),
				section(
					"Хранилище",
					node.port ? html("p", {}, html("code", {}, node.port)) : undefined,
				),
				section(
					"Аудит",
					node.audit ? html("p", {}, html("code", {}, node.audit)) : undefined,
				),
				section(
					"Исключение",
					node.throws
						? html("p", {}, html("code", {}, node.throws))
						: undefined,
				),
				section(
					"Коды отказа",
					node.codes
						? html(
								"div",
								{ class: "chips" },
								node.codes.map((code) => html("code", {}, code)),
							)
						: undefined,
				),
				section(
					"Где в коде",
					node.source ? sourceLink(node.source) : undefined,
				),
				section(
					"Путей через этот узел",
					html("p", {}, `${reaching} из ${paths.length}`),
				),
				node.jump
					? html(
							"p",
							{},
							html(
								"button",
								{
									type: "button",
									class: "chip-button",
									onclick: () => openNode(node.jump.flow, node.jump.node),
								},
								`Открыть: ${flowsById.get(node.jump.flow).title} →`,
							),
						)
					: undefined,
			]
				.flat(Number.POSITIVE_INFINITY)
				.filter((child) => child !== undefined),
		);
	};

	const renderAudit = () => {
		const canvas = byId("canvas");
		const rows = data.events.map((event) => {
			const where = [];

			for (const flow of data.flows) {
				for (const node of flow.nodes) {
					if ((node.audit ?? "").includes(event)) where.push({ flow, node });
				}
			}

			return html(
				"tr",
				{},
				html("td", {}, html("code", {}, event)),
				html(
					"td",
					{},
					...where.map(({ flow, node }) =>
						html(
							"p",
							{},
							html(
								"button",
								{
									type: "button",
									class: "chip-button",
									onclick: () => openNode(flow.id, node.id),
								},
								`${flow.title}: ${node.title}`,
							),
							" ",
							html("span", { class: "muted" }, node.audit),
						),
					),
				),
			);
		});

		canvas.replaceChildren(
			html(
				"div",
				{ style: "padding: 14px 18px" },
				html(
					"p",
					{ class: "muted" },
					"Каждое решение ядра пишет запись в приёмник аудита: событие, исход, причину, тенант, субъекта и детали. Секретов в записи нет. Ограничивающие решения (отзыв, отказ) пишутся после действия, расширяющие (выдача сессии, токена, разрешения) до: если хук аудита бросит, ничего не будет выдано.",
				),
				html(
					"table",
					{ class: "table" },
					html(
						"thead",
						{},
						html(
							"tr",
							{},
							html("th", {}, "Событие"),
							html("th", {}, "Где пишется"),
						),
					),
					html("tbody", {}, rows),
				),
			),
		);
		byId("paths").replaceChildren();
	};

	const renderPorts = () => {
		const canvas = byId("canvas");
		const map = flowsById.get("map");
		const rows = data.ports.map((port) => {
			const methods = new Map();

			for (const flow of data.flows) {
				for (const node of flow.nodes) {
					const match = node.port?.match(/^(\w+Store)\.(\w+)/);

					if (match && match[1] === port) {
						const list = methods.get(match[2]) ?? [];

						list.push({ flow, node });
						methods.set(match[2], list);
					}
				}
			}

			const portNode = map.nodes.find((node) => node.title === port);
			const adapters = map.edges
				.filter((edge) => edge.from === portNode?.id)
				.map((edge) => map.nodes.find((node) => node.id === edge.to)?.title);

			return html(
				"tr",
				{},
				html(
					"td",
					{},
					html("code", {}, port),
					portNode?.text
						? html("p", { class: "muted" }, portNode.text)
						: undefined,
				),
				html(
					"td",
					{},
					adapters
						.map((name) => html("code", {}, name))
						.flatMap((chip) => [chip, " "]),
				),
				html(
					"td",
					{},
					...[...methods.entries()].map(([method, users]) =>
						html(
							"p",
							{},
							html("code", {}, method),
							" ",
							...users.map(({ flow, node }) =>
								html(
									"button",
									{
										type: "button",
										class: "chip-button",
										onclick: () => openNode(flow.id, node.id),
									},
									`${flow.title}`,
								),
							),
						),
					),
				),
			);
		});

		canvas.replaceChildren(
			html(
				"div",
				{ style: "padding: 14px 18px" },
				html(
					"p",
					{ class: "muted" },
					"Порт это контракт хранилища, который ядро требует; адаптер отвечает на него. Каждый адаптер обязан пройти одни и те же контрактные тесты.",
				),
				html(
					"table",
					{ class: "table" },
					html(
						"thead",
						{},
						html(
							"tr",
							{},
							html("th", {}, "Порт"),
							html("th", {}, "Адаптеры"),
							html("th", {}, "Какие методы и где вызываются"),
						),
					),
					html("tbody", {}, rows),
				),
			),
		);
		byId("paths").replaceChildren();
	};

	const render = () => {
		const special = state.view !== "flow";
		const flow = currentFlow();

		byId("flow-title").textContent = special
			? SPECIAL_PAGES[state.view]
			: flow.title;
		byId("flow-summary").textContent = special ? "" : flow.summary;
		document.querySelector(".tools").hidden = special;
		byId("legend").hidden = special;
		byId("paths").hidden = special;
		renderNav();
		renderDetails();

		if (state.view === "audit") renderAudit();
		else if (state.view === "ports") renderPorts();
		else {
			renderDiagram();
			renderPaths();
		}

		const hash = special
			? `#${state.view}`
			: state.nodeId === undefined
				? `#${state.flowId}`
				: `#${state.flowId}/${state.nodeId}`;

		if (location.hash !== hash) history.replaceState(null, "", hash);
	};

	const openFlow = (flowId) => {
		state.view = "flow";
		state.flowId = flowId;
		state.nodeId = undefined;
		state.pathIndex = undefined;
		state.zoom = fitZoom();
		byId("canvas").scrollTo(0, 0);
		render();
	};

	const openSpecial = (id) => {
		state.view = id;
		state.nodeId = undefined;
		state.pathIndex = undefined;
		render();
	};

	const selectNode = (nodeId) => {
		state.nodeId = state.nodeId === nodeId ? undefined : nodeId;
		state.pathIndex = undefined;
		render();
	};

	const openNode = (flowId, nodeId) => {
		state.view = "flow";
		state.flowId = flowId;
		state.nodeId = nodeId;
		state.pathIndex = undefined;
		render();

		const target = [...document.querySelectorAll(".node.selected")][0];

		target?.scrollIntoView({ block: "center", inline: "center" });
	};

	const fitZoom = (minimum = 0.55) => {
		const layout = layoutFlow(currentFlow());
		const available = byId("canvas").clientWidth - 8;

		return Math.max(minimum, Math.min(1.2, available / layout.width));
	};

	const fit = () => {
		state.zoom = fitZoom(0.3);
		render();
	};

	const fromHash = () => {
		const [target, node] = decodeURIComponent(location.hash.slice(1)).split(
			"/",
		);

		if (target in SPECIAL_PAGES) {
			state.view = target;
		} else if (flowsById.has(target)) {
			if (state.flowId !== target || state.view !== "flow")
				byId("canvas").scrollTo(0, 0);

			state.view = "flow";
			state.flowId = target;
			state.nodeId =
				node &&
				flowsById.get(target).nodes.some((candidate) => candidate.id === node)
					? node
					: undefined;
		}
	};

	const initialRoot = () => {
		try {
			const saved = localStorage.getItem("flow-map-root");

			if (saved) return saved;
		} catch {
			return deriveRoot();
		}

		return deriveRoot();
	};

	const deriveRoot = () => {
		if (location.protocol !== "file:") return "";

		const path = decodeURIComponent(location.pathname).replace(
			/^\/(?=[A-Za-z]:)/,
			"",
		);
		const marker = "/examples/flow-map/";
		const index = path.indexOf(marker);

		return index === -1 ? "" : path.slice(0, index);
	};

	const start = () => {
		const total = data.flows.reduce((sum, flow) => sum + flow.nodes.length, 0);

		byId("stamp").textContent =
			`${data.flows.length} путей, ${total} узлов, привязаны к строкам кода`;
		state.root = initialRoot();
		byId("root").value = state.root;
		byId("root").addEventListener("input", (event) => {
			state.root = event.target.value.trim();

			try {
				localStorage.setItem("flow-map-root", state.root);
			} catch {
				state.root = event.target.value.trim();
			}

			renderDetails();
		});
		byId("search").addEventListener("input", (event) => {
			state.query = event.target.value;
			renderNav();
		});
		byId("zoom-in").addEventListener("click", () => {
			state.zoom = Math.min(2, state.zoom + 0.15);
			render();
		});
		byId("zoom-out").addEventListener("click", () => {
			state.zoom = Math.max(0.3, state.zoom - 0.15);
			render();
		});
		byId("zoom-fit").addEventListener("click", fit);
		window.addEventListener("hashchange", () => {
			fromHash();
			render();
		});
		renderLegend();
		fromHash();
		state.zoom = fitZoom();
		render();
	};

	start();
})();
