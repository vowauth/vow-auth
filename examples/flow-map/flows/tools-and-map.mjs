import { edge, flow, node } from "./dsl.mjs";

export const startup = flow(
	"startup",
	"Запуск и инструменты",
	"Запуск: createAuth",
	"Единая точка сборки ядра. Хук аудита один на все части: построить часть без него нельзя. Ошибки настройки бросаются здесь, при старте, до первого запроса.",
	[
		node("start", "start", "createAuth(options)", {
			fn: "createAuth",
			where: "packages/core/src/auth.ts#export function createAuth",
			input:
				"{ identities, epochs, tokenStore, meterStore, secrets, maximumLifeTimeMilliseconds, sessionTimeToLiveMilliseconds, stepUpTimeToLiveMilliseconds?, policy, audit }",
			output: "Auth",
		}),
		node("d-audit", "decision", "audit это функция?", {
			text: "Аудит обязателен намеренно. Не нужен вам: передайте приёмник, который ничего не делает.",
			throws: "TypeError",
		}),
		node("d-ttl", "decision", "Срок сессии не больше максимального?", {
			text: "Раньше это бросало бы на первом входе; теперь при старте.",
			throws: "RangeError",
		}),
		node("throw", "end-fail", "Исключение при старте", {
			text: "Приложение не запускается: лучше упасть сразу, чем узнать о неверной настройке, когда кто-то входит.",
			codes: ["TypeError", "RangeError"],
		}),
		node("sealer", "step", "createSealer", {
			where: "packages/core/src/sealer.ts#export function createSealer",
			text: "Секреты: хотя бы один, версии без повторов, длина не меньше порога, первый запечатывает, любой расшифровывает.",
			throws: "RangeError",
		}),
		node("tokens", "step", "createTokens", {
			where: "packages/core/src/tokens/tokens.ts#export function createTokens",
		}),
		node("meter", "step", "createMeter", {
			where: "packages/core/src/meter/meter.ts#export function createMeter",
		}),
		node("session-tokens", "step", "createSessionTokens", {
			where:
				"packages/core/src/session-tokens/session-tokens.ts#export function createSessionTokens",
			text: "Принимает sealer и хранилище эпох; максимум срока токена.",
			throws: "RangeError",
		}),
		node("mutate", "step", "createMutateIdentity", {
			where:
				"packages/core/src/identity/mutate-identity.ts#export function createMutateIdentity",
		}),
		node("sign-in", "step", "createSignIn", {
			where: "packages/core/src/sign-in.ts#export function createSignIn",
			text: "Срок сессии и срок продолжения step-up превращаются в Duration; плохое число бросает RangeError.",
			throws: "RangeError",
		}),
		node("auth", "end-ok", "Auth", {
			output:
				"{ signIn, sessions: { verify, revoke }, agents: { delegate, verify }, tokens, meter, sealer, mutateIdentity }",
			text: "Строительные блоки (issueSession, verifyProof, evaluatePolicy...) в публичный API не входят и не попадают в пакет.",
		}),
	],
	[
		edge("start", "d-audit"),
		edge("d-audit", "throw", "нет", "fail"),
		edge("d-audit", "d-ttl", "да", "branch"),
		edge("d-ttl", "throw", "нет", "fail"),
		edge("d-ttl", "sealer", "да", "branch"),
		edge("sealer", "tokens"),
		edge("tokens", "meter"),
		edge("meter", "session-tokens"),
		edge("session-tokens", "mutate"),
		edge("mutate", "sign-in"),
		edge("sealer", "throw", "плохие секреты", "fail"),
		edge("sign-in", "auth"),
	],
);

export const doctor = flow(
	"doctor",
	"Запуск и инструменты",
	"Доктор",
	"CLI для CI и локальной проверки: гоняет пробы на ваших хранилищах и факторах и печатает минимальный сценарий взлома для каждой находки. Пишет только ключи с префиксом vow-doctor-, запускайте на тестовом окружении.",
	[
		node("start", "start", "vow-auth-doctor <модуль>", {
			fn: "main(argv, print)",
			where: "packages/doctor/src/cli.ts#export async function main",
			text: "Модуль экспортирует по умолчанию { options, factors?, suppress? } или функцию, которая это возвращает.",
			output: "код выхода",
		}),
		node("load", "step", "Загрузить модуль", {
			fn: "load",
			where: "packages/doctor/src/cli.ts#const load = async",
		}),
		node("not-run", "end-fail", "выход 2", {
			text: "Нет аргумента, модуль не загрузился или форма не та. Прогона не было.",
		}),
		node("run", "step", "Прогнать пробы", {
			fn: "runDoctor",
			where:
				"packages/doctor/src/run-doctor.ts#export async function runDoctor",
			text: "Каждая проба в try/catch: проба, которая бросила (хранилище недоступно), это находка, а не молчаливый пропуск.",
		}),
		node("checks", "step", "Семь проб", {
			text: "config (createAuth принимает настройки), secrets (слабые секреты: мало разных символов, повтор, заготовки), token store (32 параллельных take отдают запись одному), epoch store (штампы строго растут), meter store (40 параллельных запросов при лимите 10), identity store (один субъект на идентичность, тенанты разделены), factors (отказ на пустое доказательство).",
		}),
		node("d-suppress", "decision", "Находка в списке suppress?", {
			text: "Подавленные уходят из вердикта, но остаются в отчёте.",
		}),
		node("report", "step", "Отчёт", {
			fn: "formatReport",
			where:
				"packages/doctor/src/format-report.ts#export function formatReport",
			text: "PASS / SKIP / ERROR. У каждой находки: заголовок, шаги «как это эксплуатируется», исправление, ключ подавления.",
		}),
		node("d-errors", "decision", "Есть ошибки?", {}),
		node("exit1", "end-fail", "выход 1"),
		node("exit0", "end-ok", "выход 0"),
	],
	[
		edge("start", "load"),
		edge("load", "not-run", "сбой", "fail"),
		edge("load", "run", "ок", "branch"),
		edge("run", "checks"),
		edge("checks", "d-suppress"),
		edge("d-suppress", "report", "да: в SKIP / нет: в находки", "branch"),
		edge("report", "d-errors"),
		edge("d-errors", "exit1", "да", "fail"),
		edge("d-errors", "exit0", "нет", "branch"),
	],
);

export const map = flow(
	"map",
	"Обзор",
	"Карта слоёв",
	"Как устроено целиком. Приложение вызывает поверхность Auth; части ядра делают работу и через порты ходят в хранилища; адаптеры отвечают на порты. Аудит один на все части. Кликните узел, чтобы открыть его путь.",
	[
		node("app", "start", "Ваше приложение", {
			layer: 0,
			text: "Маршруты HTTP, фоновые задачи. Вызывает поверхность Auth напрямую или через клиент сервиса.",
		}),
		node("service", "step", "Сервис по сети", {
			layer: 1,
			text: "Клиент и обработчик: те же формы ответов, сбой сети всегда отказ.",
			jump: { flow: "service-server", node: "start" },
		}),
		node("surface", "step", "Auth (createAuth)", {
			layer: 2,
			fn: "createAuth",
			where: "packages/core/src/auth.ts#export function createAuth",
			text: "Единственная публичная точка входа в ядро.",
			jump: { flow: "startup", node: "start" },
		}),
		node("s-signin", "step", "signIn", {
			layer: 3,
			text: "Единственная дорога к сессии.",
			jump: { flow: "sign-in", node: "start" },
		}),
		node("s-sessions", "step", "sessions.verify / revoke", {
			layer: 3,
			jump: { flow: "session-verify", node: "start" },
		}),
		node("s-agents", "step", "agents.delegate / verify", {
			layer: 3,
			jump: { flow: "agent-delegate", node: "start" },
		}),
		node("s-tokens", "step", "tokens", {
			layer: 3,
			jump: { flow: "tokens", node: "i-start" },
		}),
		node("s-meter", "step", "meter", {
			layer: 3,
			jump: { flow: "meter", node: "start" },
		}),
		node("s-sealer", "step", "sealer", {
			layer: 3,
			jump: { flow: "sealer", node: "s-start" },
		}),
		node("s-mutate", "step", "mutateIdentity", {
			layer: 3,
			jump: { flow: "identity", node: "start" },
		}),
		node("p-proof", "step", "verifyProof", {
			layer: 4,
			where: "packages/core/src/proof.ts#export async function verifyProof",
			text: "Фактор плагина → Proof.",
		}),
		node("p-resolve", "step", "resolveIdentity", {
			layer: 4,
			where:
				"packages/core/src/identity/resolve-identity.ts#export async function resolveIdentity",
		}),
		node("p-policy", "step", "evaluatePolicy / issueSession", {
			layer: 4,
			where:
				"packages/core/src/decision.ts#export async function evaluatePolicy",
			text: "Политика решает; только решение allow превращается в сессию.",
		}),
		node("p-session-tokens", "step", "sessionTokens", {
			layer: 4,
			where:
				"packages/core/src/session-tokens/session-tokens.ts#export function createSessionTokens",
			text: "Цепочка уровней с штампами; выпуск, проверка, отзыв, агенты.",
		}),
		node("p-sealer", "step", "sealer", {
			layer: 5,
			where: "packages/core/src/sealer.ts#export function createSealer",
		}),
		node("p-tokens", "step", "tokens", {
			layer: 4,
			where: "packages/core/src/tokens/tokens.ts#export function createTokens",
		}),
		node("p-meter", "step", "meter", {
			layer: 4,
			where: "packages/core/src/meter/meter.ts#export function createMeter",
		}),
		node("p-mutate", "step", "mutateIdentity", {
			layer: 4,
			where:
				"packages/core/src/identity/mutate-identity.ts#export function createMutateIdentity",
		}),
		node("p-outbox", "step", "emit / воркер outbox", {
			layer: 2,
			where: "packages/core/src/outbox/emit.ts#export function createEmit",
			text: "Живут рядом с Auth, а не внутри него: приложение зовёт emit из запроса, а воркер из планировщика.",
			jump: { flow: "outbox", node: "e-start" },
		}),
		node("port-identity", "port", "IdentityStore", {
			layer: 6,
			where:
				"packages/core/src/identity/identity-store.ts#export type IdentityStore",
			text: "Субъекты и их идентичности. Атомарно и «первый выигрывает».",
		}),
		node("port-epoch", "port", "EpochStore", {
			layer: 6,
			where:
				"packages/core/src/session-tokens/epoch-store.ts#export type EpochStore",
			text: "Штампы отзыва и единственные часы токенов.",
		}),
		node("port-token", "port", "TokenStore", {
			layer: 6,
			where: "packages/core/src/tokens/token-store.ts#export type TokenStore",
			text: "Одноразовые записи: атомарный take.",
		}),
		node("port-meter", "port", "MeterStore", {
			layer: 6,
			where: "packages/core/src/meter/meter-store.ts#export type MeterStore",
			text: "Счётчики скользящего окна.",
		}),
		node("port-outbox", "port", "OutboxStore", {
			layer: 6,
			where: "packages/core/src/outbox/outbox-store.ts#export type OutboxStore",
			text: "События наружу: append, claim с арендой, complete, release, bury.",
		}),
		node("memory", "adapter", "adapter-memory", {
			layer: 7,
			where:
				"packages/adapter-memory/src/memory-identity-store.ts#export function createMemoryIdentityStore",
			text: "Все пять портов, для тестов и разработки на одном экземпляре.",
		}),
		node("redis", "adapter", "adapter-redis", {
			layer: 7,
			where:
				"packages/adapter-redis/src/redis-epoch-store.ts#export function createRedisEpochStore",
			text: "Эпохи и счётчик (Lua, время сервера Redis).",
		}),
		node("postgres", "adapter", "adapter-postgres", {
			layer: 7,
			where:
				"packages/adapter-postgres/src/postgres-identity-store.ts#export function createPostgresIdentityStore",
			text: "Идентичности, токены, outbox. Свой исполнитель запросов.",
		}),
		node("audit", "step", "Приёмник аудита", {
			layer: 5,
			where: "packages/core/src/audit.ts#export const report",
			text: "Обязателен и общий для всех частей. Записи: событие, исход, причина, тенант, субъект, детали; секретов нет. Ограничивающие решения пишутся после, расширяющие до.",
		}),
	],
	[
		edge("app", "surface"),
		edge("app", "service"),
		edge("service", "surface"),
		edge("app", "p-outbox"),
		edge("p-outbox", "port-outbox"),
		edge("surface", "s-signin"),
		edge("surface", "s-sessions"),
		edge("surface", "s-agents"),
		edge("surface", "s-tokens"),
		edge("surface", "s-meter"),
		edge("surface", "s-sealer"),
		edge("surface", "s-mutate"),
		edge("s-signin", "p-proof"),
		edge("s-signin", "p-resolve"),
		edge("s-signin", "p-policy"),
		edge("s-signin", "p-session-tokens"),
		edge("s-sessions", "p-session-tokens"),
		edge("s-agents", "p-session-tokens"),
		edge("s-tokens", "p-tokens"),
		edge("s-meter", "p-meter"),
		edge("s-sealer", "p-sealer"),
		edge("s-mutate", "p-mutate"),
		edge("p-resolve", "port-identity"),
		edge("p-mutate", "port-identity"),
		edge("p-mutate", "port-epoch"),
		edge("p-session-tokens", "p-sealer"),
		edge("p-session-tokens", "port-epoch"),
		edge("p-tokens", "port-token"),
		edge("p-meter", "port-meter"),
		edge("port-identity", "memory"),
		edge("port-identity", "postgres"),
		edge("port-epoch", "memory"),
		edge("port-epoch", "redis"),
		edge("port-token", "memory"),
		edge("port-token", "postgres"),
		edge("port-meter", "memory"),
		edge("port-meter", "redis"),
		edge("port-outbox", "memory"),
		edge("port-outbox", "postgres"),
		edge("p-session-tokens", "audit", "report", "branch"),
	],
);
