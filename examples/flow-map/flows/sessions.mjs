import { edge, flow, node } from "./dsl.mjs";

const SESSION_TOKENS = "packages/core/src/session-tokens/session-tokens.ts";
const EPOCH_STORE = "packages/core/src/session-tokens/epoch-store.ts";

const INVALID_SESSION =
	"Один и тот же ответ на любую причину. Причина записана только в аудите (session.verify): invalid-seal, malformed-chain, expired, malformed, revoked.";

export const sessionVerify = flow(
	"session-verify",
	"Сессии и агенты",
	"Проверка сессии",
	"Горячий путь: подпись и ровно одно обращение к хранилищу эпох, ноль запросов к базе. Токен не хранится на сервере, поэтому отзыв работает через штампы эпох.",
	[
		node("start", "start", "sessions.verify(token)", {
			fn: "auth.sessions.verify",
			where: `${SESSION_TOKENS}#const verifySession = async`,
			text: "Приложение проверяет токен на каждом запросе.",
			input: "строка-токен из cookie или заголовка",
			output: "Result<VerifiedSession>",
		}),
		node("unseal", "step", "Расшифровать и проверить печать", {
			fn: "sealer.unseal(token, 'session')",
			where: "packages/core/src/sealer.ts#async unseal(sealed, purpose)",
			text: "Версия секрета → ключ HKDF → AES-GCM. Цель «session» входит в ключ: токен агента здесь не расшифруется. Локальный срок печати тоже проверяется (внешняя граница).",
			jump: { flow: "sealer", node: "u-start" },
			audit: "seal.unseal (отказ)",
		}),
		node("chain", "step", "Разобрать цепочку", {
			fn: "parseChain",
			where: `${SESSION_TOKENS}#const parseChain = (`,
			text: "Допустима только форма тенант → пользователь → устройство → сессия, каждый уровень со своим числовым штампом. Любая другая форма, порядок или тип отвергаются (A20).",
		}),
		node("read", "port", "Прочитать эпохи", {
			fn: "EpochStore.read",
			where: `${EPOCH_STORE}#export type EpochStore`,
			port: "EpochStore.read(keys)",
			text: "Один обмен: время хранилища и текущий штамп каждого уровня. Это единственное обращение к внешней системе на проверку.",
		}),
		node("d-expiry", "decision", "Срок не истёк?", {
			text: "Сравнение по часам хранилища эпох, а не по часам сервера приложения.",
		}),
		node("d-extra", "decision", "Методы и время входа на месте?", {
			text: "Токен без methods и authenticatedAtMilliseconds считается повреждённым.",
		}),
		node("d-revoked", "decision", "Штампы токена не меньше текущих?", {
			text: "Если хоть один уровень отозван (его штамп поднялся выше записанного в токене), токен мёртв. Так отзыв тенанта, пользователя, устройства или сессии убивает все токены ниже.",
		}),
		node("invalid", "end-fail", "invalid-session", {
			text: INVALID_SESSION,
			codes: ["invalid-session"],
			audit: "session.verify (refusal) с причиной и уровнем отзыва",
		}),
		node("ok", "end-ok", "VerifiedSession", {
			text: "Успех не пишется в аудит: это горячий путь.",
			output:
				"{ tenant, subject, device, session, methods, authenticatedAtMilliseconds, authenticationAgeMilliseconds }",
		}),
	],
	[
		edge("start", "unseal"),
		edge("unseal", "invalid", "печать не сошлась", "fail"),
		edge("unseal", "chain"),
		edge("chain", "invalid", "форма не та", "fail"),
		edge("chain", "read"),
		edge("read", "d-expiry"),
		edge("d-expiry", "invalid", "истёк", "fail"),
		edge("d-expiry", "d-extra", "да", "branch"),
		edge("d-extra", "invalid", "нет", "fail"),
		edge("d-extra", "d-revoked", "да", "branch"),
		edge("d-revoked", "invalid", "отозван", "fail"),
		edge("d-revoked", "ok", "да", "branch"),
	],
);

export const revoke = flow(
	"revoke",
	"Сессии и агенты",
	"Отзыв",
	"Отзыв поднимает штамп уровня в хранилище эпох. Токены ничего не хранят о себе, поэтому каждый токен с этим уровнем в цепочке перестаёт проходить проверку сразу.",
	[
		node("start", "start", "sessions.revoke(level)", {
			fn: "auth.sessions.revoke",
			where: `${SESSION_TOKENS}#async revoke(level)`,
			text: "Приложение отзывает один уровень: выход с устройства, «забыть все сессии», блокировка пользователя, отзыв агента или разрешения.",
			input:
				"{ tenant, scope: tenant | user | device | session | agent | delegation, id }",
		}),
		node("key", "step", "Ключ уровня", {
			text: "{тенант}:уровень:id. Для уровня tenant id равен самому тенанту. Все ключи тенанта лежат в одном слоте Redis Cluster.",
		}),
		node("bump", "port", "Поднять штамп", {
			fn: "EpochStore.revoke",
			where: `${EPOCH_STORE}#export type EpochStore`,
			port: "EpochStore.revoke(key, timeToLive)",
			text: "Атомарно ставит штамп max(текущий + 1, now) по часам хранилища. Штамп никогда не уменьшается. Срок жизни ключа равен максимальному сроку токена, поэтому ключ переживёт любой выданный токен.",
			throws:
				"Сбой хранилища пробрасывается: отзыв не должен молча не сработать.",
		}),
		node("audit", "step", "Запись в аудит", {
			text: "После отзыва, чтобы сбой хука аудита не мог его заблокировать.",
			audit: "session.revoke",
		}),
		node("ok", "end-ok", "Готово", {
			text: "Каскад вниз по цепочке:",
			output:
				"tenant → все; user → все сессии и все агенты человека; device → сессии устройства и привязанные к ним агенты; session → эта сессия и привязанные агенты; agent → делегирования этому агенту у всех людей; delegation → только это разрешение",
		}),
	],
	[
		edge("start", "key"),
		edge("key", "bump"),
		edge("bump", "audit"),
		edge("audit", "ok"),
	],
);

export const agentDelegate = flow(
	"agent-delegate",
	"Сессии и агенты",
	"Агенты: делегирование",
	"Человек разрешает агенту действовать от его имени. Делегируют по токену живой сессии: ядро само её проверяет, поэтому подделать делегирующего или выйти за тенант нельзя.",
	[
		node("start", "start", "agents.delegate(sessionToken, input)", {
			fn: "auth.agents.delegate",
			where: `${SESSION_TOKENS}#async delegate(sessionToken, input)`,
			input: "токен сессии, { agent, timeToLive: Duration, boundToSession? }",
			output: "Result<{ token, delegation }>",
		}),
		node("verify", "jump", "Проверить сессию делегирующего", {
			fn: "verifySession",
			text: "Тот же путь, что проверка сессии. Токен агента здесь не подойдёт: агентом нельзя делегировать дальше.",
			jump: { flow: "session-verify", node: "start" },
		}),
		node("bad-session", "end-fail", "invalid-session", {
			codes: ["invalid-session"],
		}),
		node("d-input", "decision", "Имя и срок годятся?", {
			text: "Имя агента: непустой текст без управляющих символов. Срок: Duration из defineDuration не больше максимума.",
		}),
		node("bad-input", "end-fail", "invalid-request", {
			codes: ["invalid-request"],
		}),
		node("d-bound", "decision", "Привязать к сессии?", {
			text: "С привязкой агент живёт, пока жива сессия (и устройство) делегирующего. Без привязки переживает выход, как OAuth-разрешение.",
		}),
		node("chain4", "step", "Цепочка из 4 звеньев", {
			text: "тенант → пользователь → агент → делегирование",
		}),
		node("chain6", "step", "Цепочка из 6 звеньев", {
			text: "тенант → пользователь → устройство → сессия → агент → делегирование",
		}),
		node("audit", "step", "Запись в аудит", {
			text: "До запечатывания: если хук аудита бросит, токена не будет.",
			audit: "delegation.grant { agent, delegation, bound }",
		}),
		node("read", "port", "Прочитать эпохи", {
			fn: "EpochStore.read",
			port: "EpochStore.read(keys)",
		}),
		node("seal", "step", "Запечатать токен агента", {
			fn: "sealer.seal (цель «agent»)",
			text: "Идентификатор делегирования генерирует ядро (случайный).",
			jump: { flow: "sealer", node: "s-start" },
		}),
		node("ok", "end-ok", "Delegation", {
			output: "{ token, delegation }",
			text: "Права агента лежат вне токена: приложение по id делегирования достаёт свои запреты и строит возможности через narrow.",
		}),
	],
	[
		edge("start", "verify"),
		edge("verify", "bad-session", "не сессия", "fail"),
		edge("verify", "d-input", "жива", "branch"),
		edge("d-input", "bad-input", "нет", "fail"),
		edge("d-input", "d-bound", "да", "branch"),
		edge("d-bound", "chain4", "нет", "branch"),
		edge("d-bound", "chain6", "да", "branch"),
		edge("chain4", "audit"),
		edge("chain6", "audit"),
		edge("audit", "read"),
		edge("read", "seal"),
		edge("seal", "ok"),
	],
);

export const agentVerify = flow(
	"agent-verify",
	"Сессии и агенты",
	"Агенты: проверка токена",
	"Отдельная проверка, а не поле в sessions.verify: приложение, которое про агентов не знает, их не примет, а токен агента не сойдёт за человека.",
	[
		node("start", "start", "agents.verify(token)", {
			fn: "auth.agents.verify",
			where: `${SESSION_TOKENS}#async verifyAgent(token)`,
			output: "Result<VerifiedAgent>",
		}),
		node("unseal", "step", "Расшифровать (цель «agent»)", {
			fn: "sealer.unseal(token, 'agent')",
			text: "Токен сессии здесь не расшифруется: другая цель входит в ключ.",
			jump: { flow: "sealer", node: "u-start" },
		}),
		node("chain", "step", "Разобрать цепочку", {
			fn: "parseChain",
			text: "Допустимы две формы: 4 звена (тенант, пользователь, агент, делегирование) или 6 (с устройством и сессией).",
		}),
		node("read", "port", "Прочитать эпохи", {
			fn: "EpochStore.read",
			port: "EpochStore.read(keys)",
		}),
		node("d-live", "decision", "Не истёк и не отозван?", {
			text: "Как у сессии: срок по часам хранилища, штампы всех звеньев. Агент умирает, если отозваны: тенант, человек, (устройство, сессия), агент или это делегирование.",
		}),
		node("invalid", "end-fail", "invalid-session", {
			text: "Тот же единый отказ; причина только в аудите (session.verify с агентом и делегированием).",
			codes: ["invalid-session"],
			audit: "session.verify (refusal)",
		}),
		node("ok", "end-ok", "VerifiedAgent", {
			output:
				"{ tenant, subject (человек), agent, delegation, boundTo | undefined, delegatedAtMilliseconds }",
		}),
	],
	[
		edge("start", "unseal"),
		edge("unseal", "invalid", "не сошлось", "fail"),
		edge("unseal", "chain"),
		edge("chain", "invalid", "форма не та", "fail"),
		edge("chain", "read"),
		edge("read", "d-live"),
		edge("d-live", "invalid", "нет", "fail"),
		edge("d-live", "ok", "да", "branch"),
	],
);
