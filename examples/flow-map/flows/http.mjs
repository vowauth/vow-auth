import { edge, flow, node } from "./dsl.mjs";

const HANDLER = "packages/http/src/handler.ts";
const COOKIE_HANDLER = "packages/http/src/cookie-handler.ts";
const BEARER_HANDLER = "packages/http/src/bearer-handler.ts";

export const httpCookie = flow(
	"http-cookie",
	"Вход",
	"HTTP: браузер (cookie)",
	"Обработчик для страниц в браузере. Токен сессии живёт только в cookie, которую не читает скрипт, и не попадает в тело ответа. Чужой сайт не может отправить запрос, заголовок Authorization не читается вовсе.",
	[
		node("start", "start", "POST /sign-in/<фактор>", {
			fn: "createCookieHandler",
			where: `${COOKIE_HANDLER}#export function createCookieHandler`,
			input: "Request (JSON, Origin, Sec-Fetch-Site, cookie)",
			output: "Response",
		}),
		node("route", "decision", "Путь и метод известны?", {
			fn: "route",
			where: `${HANDLER}#const route`,
			text: "Закрытая таблица маршрутов. Неизвестный путь: 404, не тот метод: 405 с Allow.",
		}),
		node("route-bad", "end-fail", "404 или 405", { codes: ["404", "405"] }),
		node("origin", "decision", "Запрос с нашей страницы?", {
			fn: "checkOrigin",
			where: "packages/http/src/origin.ts#export const checkOrigin",
			text: "Сначала Fetch Metadata (cross-site и none отказ), затем весь Origin (схема, хост, порт) точно по списку; Origin null никогда. Без Origin берётся Referer, а без обоих только same-origin.",
		}),
		node("origin-bad", "end-fail", "403 forbidden", { codes: ["forbidden"] }),
		node("json", "decision", "Тело: JSON-объект в пределе?", {
			fn: "readBody",
			where: `${HANDLER}#const readBody`,
			text: "Content-Type только application/json (форма с чужого сайта не пройдёт без предпроверки), предел читается по потоку, а не по заголовку.",
		}),
		node("json-bad", "end-fail", "400, 413 или 415", {
			codes: ["400", "413", "415"],
		}),
		node("limit", "decision", "Лимит попыток", {
			fn: "applyLimit",
			where: `${HANDLER}#const signIn`,
			text: "limit обязателен: лимитер или явное off. Забытое значение останавливает создание обработчика.",
		}),
		node("limit-bad", "end-fail", "429 и Retry-After", {
			codes: ["rate-limited"],
		}),
		node("device", "step", "Устройство браузера", {
			fn: "deviceFor",
			where: `${COOKIE_HANDLER}#async deviceFor`,
			text: "Запечатанная cookie __Host-vow-device (случайный id, цель device). Подделанная или чужая печать не доверяется, выдаётся новое устройство.",
		}),
		node("sign-in", "jump", "auth.signIn", {
			text: "Дальше путь входа ядра.",
			jump: { flow: "sign-in", node: "start" },
		}),
		node("refused", "end-fail", "Отказ или step-up", {
			text: "Один общий код на операцию; требование второго фактора возвращает continuation, cookie сессии не ставится.",
		}),
		node("cookie", "end-ok", "200 и Set-Cookie", {
			fn: "signedIn",
			where: `${COOKIE_HANDLER}#signedIn`,
			text: "HttpOnly, Secure, __Host-, Path=/, без Domain, явный SameSite (Lax по умолчанию, Strict по выбору). Токена в теле нет.",
		}),
	],
	[
		edge("start", "route"),
		edge("route", "route-bad", "нет", "fail"),
		edge("route", "origin", "да"),
		edge("origin", "origin-bad", "нет", "fail"),
		edge("origin", "json", "да"),
		edge("json", "json-bad", "нет", "fail"),
		edge("json", "limit", "да"),
		edge("limit", "limit-bad", "выше предела", "fail"),
		edge("limit", "device", "в пределах или off"),
		edge("device", "sign-in"),
		edge("sign-in", "refused", "отказ", "fail"),
		edge("sign-in", "cookie", "вход"),
	],
);

export const httpBearer = flow(
	"http-bearer",
	"Вход",
	"HTTP: приложение или сервер (Bearer)",
	"Обработчик для клиентов, которые носят токен сами. Токен приходит в теле, cookie не ставятся и не читаются, поэтому браузер нельзя заставить говорить от имени человека. Для страниц в браузере есть CORS по точному списку.",
	[
		node("start", "start", "POST /sign-in/<фактор>", {
			fn: "createBearerHandler",
			where: `${BEARER_HANDLER}#export function createBearerHandler`,
			input: "Request (JSON, device, Authorization)",
			output: "Response",
		}),
		node("preflight", "decision", "Предпроверка браузера (OPTIONS)?", {
			fn: "preflight",
			where: `${BEARER_HANDLER}#preflight`,
			text: "Отвечает только источникам из allowedOrigins, точно по значению, без звёздочки и без credentials.",
		}),
		node("preflight-bad", "end-fail", "403 без CORS-заголовков", {
			codes: ["forbidden"],
		}),
		node("json", "decision", "Тело: JSON-объект в пределе?", {
			fn: "readBody",
			where: `${HANDLER}#const readBody`,
		}),
		node("json-bad", "end-fail", "400, 413 или 415", {
			codes: ["400", "413", "415"],
		}),
		node("limit", "decision", "Лимит попыток", {
			fn: "applyLimit",
			where: `${HANDLER}#const signIn`,
		}),
		node("limit-bad", "end-fail", "429 и Retry-After", {
			codes: ["rate-limited"],
		}),
		node(
			"device",
			"decision",
			"device: случайная строка не короче 16 знаков?",
			{
				fn: "deviceFor",
				where: `${BEARER_HANDLER}#async deviceFor`,
				text: "Имя вроде phone отвергается: от device зависит, что завершит выход с устройства.",
			},
		),
		node("device-bad", "end-fail", "400 invalid-request", {
			codes: ["invalid-request"],
		}),
		node("sign-in", "jump", "auth.signIn", {
			text: "Дальше путь входа ядра.",
			jump: { flow: "sign-in", node: "start" },
		}),
		node("refused", "end-fail", "Отказ или step-up", {}),
		node("token", "end-ok", "200 и токен в теле", {
			fn: "signedIn",
			where: `${BEARER_HANDLER}#signedIn`,
			text: "Set-Cookie нет. Дальше клиент шлёт Authorization: Bearer <токен>; токен в адресе не читается.",
		}),
	],
	[
		edge("start", "preflight"),
		edge("preflight", "preflight-bad", "источника нет в списке", "fail"),
		edge("preflight", "json", "не OPTIONS"),
		edge("json", "json-bad", "нет", "fail"),
		edge("json", "limit", "да"),
		edge("limit", "limit-bad", "выше предела", "fail"),
		edge("limit", "device", "в пределах или off"),
		edge("device", "device-bad", "нет", "fail"),
		edge("device", "sign-in", "да"),
		edge("sign-in", "refused", "отказ", "fail"),
		edge("sign-in", "token", "вход"),
	],
);
