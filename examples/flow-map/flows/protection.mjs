import { edge, flow, node } from "./dsl.mjs";

const METER = "packages/core/src/meter/meter.ts";
const METER_STORE = "packages/core/src/meter/meter-store.ts";

export const meter = flow(
	"meter",
	"Защита",
	"Счётчик запросов",
	"Скользящее окно как у Cloudflare: два счётчика на ключ, оценка = прошлый × (окно − прошло) / окно + текущий. Отказанный запрос ничего не считает и получает точный момент, когда пройдёт.",
	[
		node("define", "start", "defineMeterRule({ limit, windowMilliseconds })", {
			fn: "defineMeterRule",
			where: `${METER}#export const defineMeterRule`,
			text: "Правило определяется один раз при старте. Не бросает: плохие числа (не положительные целые) дают invalid-request. Запросный API принимает только такое правило.",
			output: "Result<MeterRule>",
			codes: ["invalid-request"],
		}),
		node("start", "start", "meter.consume(scope, rule, cost = 1)", {
			fn: "auth.meter.consume",
			where: `${METER}#async consume(scope, rule, cost = 1)`,
			text: "observe(scope, rule, cost) идёт тем же путём, но никогда не отказывает: запрос, который consume отказал бы, пропускается и пишется в аудит как наблюдение (выкатка нового лимита).",
			input: "{ tenant, actor, resource }, MeterRule, cost",
			output: "Result<{ used, remaining, resetsAtMilliseconds }, MeterRefusal>",
		}),
		node(
			"d-valid",
			"decision",
			"Правило выдано defineMeterRule, цена целая и не больше лимита?",
			{
				fn: "decide",
				where: `${METER}#const decide = async`,
				text: "Цена это данные запроса, поэтому её проверка отказ, а не исключение. Ничего не считается.",
			},
		),
		node("bad", "end-fail", "invalid-request", {
			codes: ["invalid-request"],
		}),
		node("store", "port", "Посчитать", {
			fn: "MeterStore.consume",
			where: `${METER_STORE}#export type MeterStore`,
			port: "MeterStore.consume({ key, cost, limit, windowMilliseconds })",
			text: "Один атомарный шаг по часам самого хранилища, решает как slidingWindow. Нет места под ключ: отказ (refusedForCapacity), а не пропуск. Redis: Lua; память: синхронно.",
		}),
		node("d-allowed", "decision", "Укладывается в лимит?", {}),
		node("ok", "end-ok", "Reading", {
			text: "Успехи в аудит не пишутся: это горячий путь.",
			output: "{ used, remaining, resetsAtMilliseconds }",
		}),
		node("audit", "step", "Запись отказа в аудит", {
			audit: "meter.consume (refusal), причина limit-exceeded | capacity",
		}),
		node("limited", "end-fail", "rate-limited", {
			output: "{ code: rate-limited, resetsAtMilliseconds }",
			text: "Приложение отвечает 429 и Retry-After по resetsAtMilliseconds.",
			codes: ["rate-limited"],
		}),
	],
	[
		edge("start", "d-valid"),
		edge("d-valid", "bad", "нет", "fail"),
		edge("d-valid", "store", "да", "branch"),
		edge("store", "d-allowed"),
		edge("d-allowed", "ok", "да", "branch"),
		edge("d-allowed", "audit", "нет", "fail"),
		edge("audit", "limited"),
	],
);

export const authorizeFlow = flow(
	"authorize",
	"Защита",
	"Права после входа",
	"Решение «можно ли этому субъекту это действие над этим ресурсом». Правила это сериализуемые данные (vetojs). По умолчанию запрет; делегат получает подмножество прав делегирующего.",
	[
		node("start", "start", "authorize(ability, request, context)", {
			fn: "authorize",
			where:
				"packages/authorize/src/authorize.ts#export async function authorize",
			input: "Ability, { action, resource, row? }, { tenant, subject, audit }",
			output: "Result<undefined>",
		}),
		node("check", "step", "Спросить возможности", {
			fn: "ability.authorize (vetojs)",
			text: "Выбрасывает ForbiddenError на запрете. Любое другое исключение (например, не загруженная связь) это ошибка проверки.",
		}),
		node("d-result", "decision", "Что случилось?", {}),
		node("audit", "step", "Запись вердикта", {
			text: "Каждый вердикт пишется до возврата: если хук бросит, нет и allow.",
			audit: "authorize.check, reason: allowed | forbidden | authorize-error",
		}),
		node("d-allowed", "decision", "Разрешено?", {}),
		node("ok", "end-ok", "ok"),
		node("forbidden", "end-fail", "forbidden", {
			codes: ["forbidden"],
			text: "Запрет и ошибка проверки дают один ответ. Закрыто.",
		}),
		node("n-start", "start", "narrow(ac, delegator, denies)", {
			fn: "narrow",
			where: "packages/authorize/src/narrow.ts#export function narrow",
			text: "Права агента из прав делегирующего плюс дополнительные запреты. Расширить права нельзя: любое правило, кроме deny, отклоняет делегирование.",
			input: "карта ресурсов, Ability делегирующего, CheckedRule[]",
			output: "Result<Ability>",
		}),
		node("n-denies", "decision", "Все правила это deny?", {}),
		node("n-bad", "end-fail", "invalid-delegation", {
			codes: ["invalid-delegation"],
		}),
		node("n-ok", "end-ok", "Ability делегата", {
			text: "Права делегата всегда подмножество прав делегирующего, а его ограничения сохраняются (property-тест).",
		}),
	],
	[
		edge("start", "check"),
		edge("check", "d-result"),
		edge(
			"d-result",
			"audit",
			"разрешено / ForbiddenError / иная ошибка",
			"branch",
		),
		edge("audit", "d-allowed"),
		edge("d-allowed", "ok", "allowed", "branch"),
		edge("d-allowed", "forbidden", "иначе", "fail"),
		edge("n-start", "n-denies"),
		edge("n-denies", "n-bad", "нет", "fail"),
		edge("n-denies", "n-ok", "да", "branch"),
	],
);

export const transport = flow(
	"transport",
	"Защита",
	"Редиректы и исходящие вызовы",
	"Две проверки на границе: куда можно отправить браузер после входа (открытые редиректоры, RFC 9700) и куда может ходить приложение само (SSRF, OWASP).",
	[
		node("r-start", "start", "redirect(target)", {
			fn: "createRedirectPolicy(options)(target)",
			where:
				"packages/core/src/transport/redirect-policy.ts#export function createRedirectPolicy",
			text: "Список разрешённых origin проверяется при создании (бросок RangeError при старте): точные origin, без шаблонов, http только для loopback.",
			output: "Result<строка для Location>",
		}),
		node("r-text", "decision", "Строка допустима?", {
			text: "Текст до 2048 знаков без обратной косой, управляющих символов и пробелов любого письма: браузер читает такие строки иначе, чем проверяющий.",
		}),
		node("r-bad", "end-fail", "invalid-request", {
			codes: ["invalid-request"],
		}),
		node("r-path", "decision", "Начинается с «/»?", {}),
		node("r-double", "decision", "Начинается с «//»?", {
			text: "«//evil.com» это адрес другого сайта.",
		}),
		node("r-path-ok", "end-ok", "Путь этого сайта"),
		node(
			"r-origin",
			"decision",
			"Абсолютный URL с origin из списка, без логина и пароля?",
			{
				text: "Точное совпадение origin (схема, хост, порт).",
			},
		),
		node("r-url-ok", "end-ok", "Нормализованный URL"),
		node("o-start", "start", "guard.fetch(target, init)", {
			fn: "createOutboundGuard(options)",
			where:
				"packages/core/src/transport/outbound-guard.ts#export function createOutboundGuard",
			text: "check(target) делает проверки, fetch(target) вызывает их и затем запрос с redirect: error и cache: no-store.",
			output: "Result<Response>",
		}),
		node(
			"o-shape",
			"decision",
			"https, порт по умолчанию, без логина, хост в списке?",
			{
				text: "Сначала список разрешённых имён, и только они. IP-адрес в качестве хоста запрещён.",
			},
		),
		node("o-forbidden", "end-fail", "forbidden", { codes: ["forbidden"] }),
		node("o-resolve", "decision", "Все адреса имени публичные?", {
			fn: "resolveAddresses + isPublicAddress",
			where:
				"packages/core/src/transport/public-address.ts#export function isPublicAddress",
			text: "Если передан резолвер: каждый адрес должен быть глобально маршрутизируемым (частные, loopback, link-local, документация, multicast, а также IPv4 внутри IPv6). Пустой ответ и сбой резолвера это запрет. Окно DNS rebinding закрывает только сетевое ограничение исходящего трафика.",
		}),
		node("o-call", "step", "Вызов без редиректов", {
			text: "fetch с redirect: error: ответ-редирект не будет принят.",
		}),
		node("o-unavailable", "end-fail", "unavailable", {
			codes: ["unavailable"],
			text: "Сбой сети.",
		}),
		node("o-ok", "end-ok", "Response"),
	],
	[
		edge("r-start", "r-text"),
		edge("r-text", "r-bad", "нет", "fail"),
		edge("r-text", "r-path", "да", "branch"),
		edge("r-path", "r-double", "да", "branch"),
		edge("r-double", "r-bad", "да", "fail"),
		edge("r-double", "r-path-ok", "нет", "branch"),
		edge("r-path", "r-origin", "нет", "branch"),
		edge("r-origin", "r-bad", "нет", "fail"),
		edge("r-origin", "r-url-ok", "да", "branch"),
		edge("o-start", "o-shape"),
		edge("o-shape", "o-forbidden", "нет", "fail"),
		edge("o-shape", "o-resolve", "да", "branch"),
		edge("o-resolve", "o-forbidden", "нет", "fail"),
		edge("o-resolve", "o-call", "да / резолвера нет", "branch"),
		edge("o-call", "o-unavailable", "сбой", "fail"),
		edge("o-call", "o-ok"),
	],
);
