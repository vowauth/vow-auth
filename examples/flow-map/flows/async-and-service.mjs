import { edge, flow, node } from "./dsl.mjs";

const OUTBOX_STORE = "packages/core/src/outbox/outbox-store.ts";
const HANDLER = "packages/service/src/handler.ts";
const CLIENT = "packages/service/src/client.ts";

export const outbox = flow(
	"outbox",
	"Асинхронность",
	"Outbox: события наружу",
	"Единственный выход из запроса во внешний мир. Событие записывается в хранилище вместе с изменением, а доставляет его воркер после запроса. Сбой получателя не ломает вход. Доставка минимум один раз.",
	[
		node("e-start", "start", "emit(event)", {
			fn: "emit",
			where: "packages/core/src/outbox/emit.ts#export function createEmit",
			input: "{ type, payload: Record<string, string> }",
			output: "Result<id>",
		}),
		node("e-shape", "decision", "Событие целое?", {
			fn: "parseEvent",
			where: "packages/core/src/outbox/emit.ts#const parseEvent",
			text: "Закрытая форма: только type и payload; type это текст, который можно хранить; значения payload строки (любой текст, включая переводы строк). Ключ вроде __proto__ остаётся обычным ключом.",
		}),
		node("e-bad", "end-fail", "invalid-event", { codes: ["invalid-event"] }),
		node("e-append", "port", "Записать событие", {
			fn: "OutboxStore.append",
			where: `${OUTBOX_STORE}#export type OutboxStore`,
			port: "OutboxStore.append({ id, type, payload })",
			text: "Должно попасть в ту же транзакцию, что и изменение, которое породило событие (Postgres: исполнитель транзакции). Повтор того же id ничего не меняет.",
		}),
		node("e-ok", "end-ok", "id события"),
		node("w-start", "start", "worker.runOnce()", {
			fn: "createOutboxWorker",
			where:
				"packages/core/src/outbox/outbox-worker.ts#export function createOutboxWorker",
			text: "Вызывайте из планировщика или потребителя очереди. Параметры проверяются при создании.",
			output: "{ completed, retried, buried }",
		}),
		node("w-claim", "port", "Забрать пачку", {
			fn: "OutboxStore.claim",
			where: `${OUTBOX_STORE}#export type OutboxStore`,
			port: "OutboxStore.claim({ limit, leaseMilliseconds })",
			text: "Прячет события от других воркеров на аренду и увеличивает attempts. Событие с истёкшей арендой снова доступно: упавший воркер ничего не теряет. Postgres: for update skip locked.",
		}),
		node("w-handler", "decision", "Есть обработчик этого типа?", {
			text: "События без обработчика закапываются сразу, чтобы опечатка не крутилась вечно.",
		}),
		node("w-run", "step", "Обработчик", {
			fn: "handler(event)",
			text: "Код приложения: письмо, вебхук. Может бросить, тогда пробуем позже. События пачки идут независимо.",
		}),
		node("w-failed", "decision", "Бросил?", {}),
		node("w-attempts", "decision", "Попыток уже не меньше предела?", {}),
		node("w-complete", "port", "Готово", {
			fn: "OutboxStore.complete",
			port: "OutboxStore.complete(record)",
			text: "Сверяет attempts: воркер с просроченной арендой не может отменить чужую выдачу.",
		}),
		node("w-release", "port", "Вернуть на повтор", {
			fn: "OutboxStore.release",
			port: "OutboxStore.release(record, retryDelay)",
		}),
		node("w-bury", "port", "Закопать", {
			fn: "OutboxStore.bury",
			port: "OutboxStore.bury(record)",
			text: "Postgres переносит запись в vow_auth_outbox_buried для разбора.",
		}),
		node("w-summary", "end-ok", "Итог прогона", {
			output: "{ completed, retried, buried }",
		}),
	],
	[
		edge("e-start", "e-shape"),
		edge("e-shape", "e-bad", "нет", "fail"),
		edge("e-shape", "e-append", "да", "branch"),
		edge("e-append", "e-ok"),
		edge("w-start", "w-claim"),
		edge("w-claim", "w-handler"),
		edge("w-handler", "w-bury", "нет", "fail"),
		edge("w-handler", "w-run", "да", "branch"),
		edge("w-run", "w-failed"),
		edge("w-failed", "w-complete", "нет", "branch"),
		edge("w-failed", "w-attempts", "да", "branch"),
		edge("w-attempts", "w-bury", "да", "fail"),
		edge("w-attempts", "w-release", "нет", "branch"),
		edge("w-complete", "w-summary"),
		edge("w-release", "w-summary"),
		edge("w-bury", "w-summary"),
	],
);

export const serviceServer = flow(
	"service-server",
	"Режим сервиса",
	"Сервис: обработчик",
	"Fetch-обработчик (Request → Response). Порядок проверок важен: сначала секрет, потом всё остальное. Каждый ответ с Cache-Control: no-store, потому что может нести токен.",
	[
		node("start", "start", "handler(request)", {
			fn: "createAuthHandler(options)",
			where: `${HANDLER}#export function createAuthHandler`,
			text: "Секреты сервиса (минимум один, каждый длиннее порога) и предел размера тела проверяются при создании.",
			input: "Request",
			output: "Response",
		}),
		node("d-secret", "decision", "Секрет верен?", {
			fn: "sameDigest",
			where: `${HANDLER}#const sameDigest`,
			text: "Authorization: Bearer. Сравниваются SHA-256 дайджесты, всегда со всеми секретами (время не зависит от того, какой подошёл), так что секрет можно ротировать списком.",
		}),
		node("r401", "end-fail", "401", {
			output: "problem+json, www-authenticate: Bearer",
			text: "Ответ одинаков для любого маршрута: список маршрутов не раскрывается неавторизованным.",
		}),
		node("d-route", "decision", "Такой маршрут есть?", {}),
		node("r404", "end-fail", "404"),
		node("d-method", "decision", "Метод POST?", {}),
		node("r405", "end-fail", "405", { output: "allow: POST" }),
		node("d-size", "decision", "Тело не больше предела?", {
			fn: "readLimited",
			where: `${HANDLER}#const readLimited = async`,
			text: "Объявленная длина и поток считаются отдельно: заниженный Content-Length не поможет.",
		}),
		node("r413", "end-fail", "413"),
		node("d-json", "decision", "UTF-8 и JSON-объект?", {}),
		node("r400", "end-fail", "400", {
			text: "Неверный JSON, не объект, лишний ключ, неверный тип. Формы запросов закрытые (hasOnlyKeys).",
		}),
		node("route", "step", "Маршрут разбирает тело", {
			text: "Проверка формы, затем вызов ядра: /v1/sign-in (фактор по id из списка через Object.hasOwn), /v1/sessions/verify, /v1/sessions/revoke, /v1/agents/delegate, /v1/agents/verify, /v1/meter/consume, /v1/meter/observe, /v1/identities/delete.",
		}),
		node("core", "jump", "Ядро решает", {
			text: "Любой отказ предметной области это обычный ответ.",
			jump: { flow: "map", node: "surface" },
		}),
		node("r200", "end-ok", "200 JSON", {
			output: "{ ok: true, value } | { ok: false, error }",
			text: "Отказ ядра (no-allow, invalid-session, rate-limited) приходит со статусом 200 и тем же видом, что в процессе.",
		}),
		node("r500", "end-fail", "500", {
			text: "Неожиданное исключение. Тело ответа не содержит причины.",
		}),
	],
	[
		edge("start", "d-secret"),
		edge("d-secret", "r401", "нет", "fail"),
		edge("d-secret", "d-route", "да", "branch"),
		edge("d-route", "r404", "нет", "fail"),
		edge("d-route", "d-method", "да", "branch"),
		edge("d-method", "r405", "нет", "fail"),
		edge("d-method", "d-size", "да", "branch"),
		edge("d-size", "r413", "нет", "fail"),
		edge("d-size", "d-json", "да", "branch"),
		edge("d-json", "r400", "нет", "fail"),
		edge("d-json", "route", "да", "branch"),
		edge("route", "r400", "форма не та", "fail"),
		edge("route", "core"),
		edge("core", "r200"),
		edge("core", "r500", "исключение", "fail"),
	],
);

export const serviceClient = flow(
	"service-client",
	"Режим сервиса",
	"Сервис: клиент",
	"Клиент отдаёт те же формы, что ядро в процессе. Главное правило: ничего неясное не становится разрешением. Сеть, таймаут, чужой статус или кривой ответ дают отказ unavailable, никогда успех.",
	[
		node("start", "start", "client.signIn / sessions.verify / ...", {
			fn: "createAuthClient(options)",
			where: `${CLIENT}#export function createAuthClient`,
			text: "Тот же поверхностный API, что у Auth: код приложения не знает, в процессе ядро или по сети.",
		}),
		node("call", "step", "POST на сервис", {
			fn: "call",
			where: `${CLIENT}#const call = async`,
			text: "fetch с секретом, redirect: error (секрет не уйдёт на другой адрес), cache: no-store, таймаут. Повторов нет: consume и mutateIdentity не идемпотентны.",
		}),
		node("d-transport", "decision", "Ответ получен?", {
			text: "Сетевая ошибка или таймаут: причина network | timeout.",
		}),
		node("d-status", "decision", "Статус 200?", {
			text: "401 и 403 это причина unauthorized; 5xx это server-error; любой другой статус это unexpected-status.",
		}),
		node("d-body", "decision", "Тело это JSON нужной формы?", {
			fn: "ask + parse*",
			where: `${CLIENT}#const ask = async`,
			text: "Строгие разборщики: ok без value, error не код, неверные типы полей это причина malformed. Успех возможен только из правильно оформленного ответа 200.",
		}),
		node("unavailable", "end-fail", "unavailable", {
			text: "Результаты возвращают fail(unavailable) (счётчик: { code: unavailable }). revoke бросает ошибку, которую узнаёт isUnavailableError: молча не отозвать хуже, чем упасть. Причину получает onUnavailable (логи, метрики), он не меняет исход.",
			codes: ["unavailable"],
		}),
		node("domain", "end-fail", "Отказ ядра", {
			text: "Ответ 200 вида { ok: false, error }: no-allow, invalid-session, rate-limited, step-up-required и так далее передаются как есть.",
		}),
		node("ok", "end-ok", "Успех ядра", {
			text: "{ ok: true, value } разобран строго.",
		}),
	],
	[
		edge("start", "call"),
		edge("call", "d-transport"),
		edge("d-transport", "unavailable", "нет", "fail"),
		edge("d-transport", "d-status", "да", "branch"),
		edge("d-status", "unavailable", "нет", "fail"),
		edge("d-status", "d-body", "да", "branch"),
		edge("d-body", "unavailable", "нет", "fail"),
		edge("d-body", "domain", "ok: false", "branch"),
		edge("d-body", "ok", "ok: true", "branch"),
	],
);
