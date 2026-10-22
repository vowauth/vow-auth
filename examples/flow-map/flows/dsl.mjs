/**
 * Kinds of node:
 * - start: where a path begins (a call of the application).
 * - step: a function that does work.
 * - decision: a branch; its edges carry the labels of the answers.
 * - port: a call to a storage port (an adapter answers it).
 * - end-ok, end-fail, end-wait: where a path ends.
 * - jump: the path goes on in another flow.
 */
export const node = (id, kind, title, details = {}) => ({
	id,
	kind,
	title,
	...details,
});

/** Kinds of edge: ok (the normal way), fail (a refusal), branch (one answer of a decision). */
export const edge = (from, to, label = "", kind = "ok") => ({
	from,
	to,
	label,
	kind,
});

export const flow = (id, group, title, summary, nodes, edges) => ({
	id,
	group,
	title,
	summary,
	nodes,
	edges,
});

export const GROUPS = [
	"Обзор",
	"Вход",
	"Сессии и агенты",
	"Данные",
	"Защита",
	"Асинхронность",
	"Режим сервиса",
	"Запуск и инструменты",
];
