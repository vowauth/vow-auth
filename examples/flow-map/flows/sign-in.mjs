import { edge, flow, node } from "./dsl.mjs";

const SIGN_IN = "packages/core/src/sign-in.ts";
const PROOF = "packages/core/src/proof.ts";
const RESOLVE = "packages/core/src/identity/resolve-identity.ts";
const DECISION = "packages/core/src/decision.ts";
const SESSION = "packages/core/src/session.ts";
const SESSION_TOKENS = "packages/core/src/session-tokens/session-tokens.ts";
const IDENTITY_STORE = "packages/core/src/identity/identity-store.ts";
const EPOCH_STORE = "packages/core/src/session-tokens/epoch-store.ts";

export const signIn = flow(
	"sign-in",
	"Вход",
	"Вход: первый шаг",
	"Единственная дорога к сессии. Любой фактор, нынешний и будущий, идёт по ней: проверка доказательства, определение субъекта, политика, выдача токена. Сессию нельзя получить, минуя этот путь.",
	[
		node("start", "start", "signIn(request)", {
			fn: "auth.signIn",
			where: `${SIGN_IN}#export function createSignIn`,
			text: "Вход в ядро. Приложение передаёт тенант, устройство, фактор (плагин) и ответ, который человек прислал этому фактору.",
			input: "{ tenant, device, factor, response, continuation? }",
			output: "Result<SignedIn, SignInRefusal>",
		}),
		node("text", "decision", "Имена можно хранить?", {
			fn: "isStorableText",
			where:
				"packages/core/src/shared/is-storable-text.ts#export const isStorableText",
			text: "tenant, device и continuation должны быть непустым текстом без управляющих символов (NUL) и одиночных суррогатов. Иначе хранилище (Postgres) не удержит значение. Проверка до любого обращения к хранилищу.",
			codes: ["invalid-request"],
		}),
		node("bad-request", "end-fail", "invalid-request", {
			text: "Запрос отвергнут на границе, ни одно хранилище не вызывалось.",
			codes: ["invalid-request"],
		}),
		node("cont", "decision", "Есть continuation?", {
			fn: "secondStep / firstStep",
			where: `${SIGN_IN}#return async (request) => {`,
			text: "continuation приходит только на втором шаге step-up. Без него идёт первый шаг.",
		}),
		node("second", "jump", "Второй шаг step-up", {
			text: "Продолжение входа после второго фактора.",
			jump: { flow: "sign-in-step-up", node: "start" },
		}),
		node("verify", "step", "Фактор проверяет ответ", {
			fn: "verifyProof",
			where: `${PROOF}#export async function verifyProof`,
			text: "Вызывает factor.verify(response) (код плагина, исключение считается отказом), проверяет claims по закрытой форме (parseClaims: provider, externalId, email, emailVerified; email канонизируется), пишет в аудит и чеканит Proof. Proof создаёт только эта функция.",
			input: "factor, response",
			output: "Proof { factor, strength, verifiedAt, claims }",
			audit: "proof.verify (успех и каждый отказ)",
			codes: ["invalid-proof"],
		}),
		node("bad-proof", "end-fail", "invalid-proof", {
			text: "Фактор отклонил ответ, бросил исключение, вернул claims непонятной формы или с недопустимой почтой. Причину знает только аудит (factor-rejected, factor-error, invalid-claims, invalid-email).",
			codes: ["invalid-proof"],
			audit:
				"proof.verify, reason: factor-rejected | factor-error | invalid-claims | invalid-email",
		}),
		node("resolve", "step", "Какой это субъект?", {
			fn: "resolveIdentity",
			where: `${RESOLVE}#export async function resolveIdentity`,
			text: "Сопоставляет доказательство с субъектом тенанта: уже знакомая идентичность, привязка к владельцу подтверждённой почты или новый субъект.",
			input: "tenant, Proof",
			output: "{ subjectId, outcome: existing | linked | created }",
			audit: "identity.resolve",
		}),
		node("find", "port", "Идентичность уже известна?", {
			fn: "IdentityStore.findSubject",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.findSubject(tenant, provider, externalId)",
			text: "Поиск по паре (provider, externalId) внутри тенанта.",
		}),
		node("d-found", "decision", "Нашли?", {}),
		node("d-verified", "decision", "Почта подтверждена?", {
			text: "Привязывать по почте можно только если фактор подтвердил владение ею (A3). Неподтверждённая почта никогда не линкует.",
		}),
		node("owner", "port", "Кто владеет подтверждённой почтой?", {
			fn: "IdentityStore.findSubjectByVerifiedEmail",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.findSubjectByVerifiedEmail(tenant, email)",
			text: "Владелец: самая ранняя идентичность, подтвердившая этот адрес.",
		}),
		node("d-owner", "decision", "Есть владелец?", {}),
		node("link", "port", "Привязать к владельцу", {
			fn: "IdentityStore.linkIdentity",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.linkIdentity(tenant, subjectId, identity)",
			text: "Атомарно и «первый выигрывает»: возвращает субъекта, которому принадлежит идентичность после вызова.",
		}),
		node("create", "port", "Создать субъекта", {
			fn: "IdentityStore.createSubject",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.createSubject(tenant, identity)",
			text: "Атомарно и «первый выигрывает». Если параллельный вход успел раньше, возвращается его субъект (isNew: false, исход existing).",
		}),
		node("resolved", "step", "Субъект определён", {
			text: "Исход existing, linked или created записан в аудит. Дальше решает политика.",
			output: "{ subjectId, outcome }",
			audit: "identity.resolve (success)",
		}),
		node("d-confirm", "decision", "emailVerified?", {
			text: "Если фактор подтвердил почту, ядро подтверждает её для субъекта и убирает чужие неподтверждённые претензии на этот адрес.",
		}),
		node("confirm", "jump", "Подтвердить почту", {
			fn: "mutateIdentity(confirm-email)",
			text: "Вытесняет неподтверждённые претензии, отзывает сессии вытесненных субъектов.",
			jump: { flow: "identity", node: "d-verified" },
		}),
		node("conclude", "step", "Решение по входу", {
			fn: "conclude",
			where: `${SIGN_IN}#const conclude = async`,
			text: "Общий финал обоих шагов входа. Спрашивает политику, потом выдаёт сессию или просит ещё фактор.",
			input:
				"subjectId, proofs (все пройденные доказательства), outcome, email, evicted",
		}),
		node("policy", "step", "Политика решает", {
			fn: "evaluatePolicy",
			where: `${DECISION}#export async function evaluatePolicy`,
			text: "Вызывает policy({ subject, tenant, proof, proofs }). Разрешением считается только точная строка «allow»; requireFactor(id) просит ещё фактор; всё остальное, включая исключение, это отказ. Решение пишется в аудит; allow записывается до выдачи.",
			audit: "policy.evaluate",
			codes: ["no-allow"],
		}),
		node("d-verdict", "decision", "Что ответила политика?", {
			fn: "judge",
			where: `${DECISION}#const judge = async`,
		}),
		node("d-stepup", "decision", "Можно просить фактор?", {
			text: "Нужны оба условия: в createAuth задан stepUpTimeToLiveMilliseconds и этот фактор ещё не пройден в этом входе. Иначе step-up превращается в отказ.",
			codes: ["no-allow"],
		}),
		node("cont-issue", "step", "Записать продолжение", {
			fn: "tokens.issue (sign-in-continuation)",
			where: `${SIGN_IN}#const continuation = await tokens.issue`,
			text: "Одноразовая запись в хранилище токенов: тенант, устройство, субъект, нужный фактор, доказательства шага 1, исход, вытесненные. Срок stepUpTimeToLiveMilliseconds.",
			jump: { flow: "tokens", node: "i-put" },
		}),
		node("end-stepup", "end-wait", "step-up-required", {
			text: "Сессия не выдана. Ошибка несёт { code: 'step-up-required', factor, continuation }: приложение просит человека пройти второй фактор и вызывает signIn с continuation. ok остаётся false.",
			output: "{ code: step-up-required, factor, continuation }",
			jump: { flow: "sign-in-step-up", node: "start" },
		}),
		node("no-allow", "end-fail", "no-allow", {
			text: "Политика не разрешила (или step-up невозможен). Токен не выдан.",
			codes: ["no-allow"],
			audit:
				"policy.evaluate, reason: not-allowed | policy-error | step-up-unavailable",
		}),
		node("born", "step", "Рождается сессия", {
			fn: "issueSession",
			where: `${SESSION}#export function issueSession`,
			text: "Принимает только allow-решение, выданное evaluatePolicy (проверка по реестру чеканки, не по форме). Создаёт Session { id (случайный), subject }.",
			codes: ["no-allow"],
		}),
		node("issue", "step", "Токен сессии", {
			fn: "sessionTokens.issue",
			where: `${SESSION_TOKENS}#async issue(session, input)`,
			text: "Проверяет, что срок это Duration не больше максимума; пишет session.issue в аудит (до выдачи); читает штампы эпох цепочки тенант → пользователь → устройство → сессия за один обмен с хранилищем; запечатывает цепочку, срок, методы входа и время входа.",
			input: "Session, { tenant, device, timeToLive, methods }",
			output: "строка-токен",
			audit: "session.issue",
			codes: ["invalid-request"],
		}),
		node("epochs", "port", "Прочитать штампы цепочки", {
			fn: "EpochStore.read",
			where: `${EPOCH_STORE}#export type EpochStore`,
			port: "EpochStore.read(keys)",
			text: "Одна атомарная операция: время хранилища и штамп каждого уровня цепочки. Штампы кладутся в токен.",
		}),
		node("seal", "step", "Запечатать", {
			fn: "sealer.seal",
			where: "packages/core/src/sealer.ts#async seal(input)",
			text: "AES-GCM с ключом из HKDF (секрет, соль, цель «session»). Результат «версия.base64url».",
			jump: { flow: "sealer", node: "s-start" },
		}),
		node("ok", "end-ok", "SignedIn", {
			text: "Сессия выдана.",
			output:
				"{ token, tenant, subject, device, session, identity, email, evicted }",
		}),
	],
	[
		edge("start", "text"),
		edge("text", "bad-request", "нет", "fail"),
		edge("text", "cont", "да", "branch"),
		edge("cont", "second", "есть", "branch"),
		edge("cont", "verify", "нет", "branch"),
		edge("verify", "bad-proof", "отказ", "fail"),
		edge("verify", "resolve"),
		edge("resolve", "find"),
		edge("find", "d-found"),
		edge("d-found", "resolved", "да: existing", "branch"),
		edge("d-found", "d-verified", "нет", "branch"),
		edge("d-verified", "create", "нет", "branch"),
		edge("d-verified", "owner", "да", "branch"),
		edge("owner", "d-owner"),
		edge("d-owner", "link", "да: linked", "branch"),
		edge("d-owner", "create", "нет", "branch"),
		edge("link", "resolved"),
		edge("create", "resolved", "created | existing"),
		edge("resolved", "d-confirm"),
		edge("d-confirm", "confirm", "да", "branch"),
		edge("d-confirm", "conclude", "нет", "branch"),
		edge("confirm", "conclude"),
		edge("conclude", "policy"),
		edge("policy", "d-verdict"),
		edge("d-verdict", "born", "allow", "branch"),
		edge("d-verdict", "d-stepup", "requireFactor", "branch"),
		edge("d-verdict", "no-allow", "любое другое", "fail"),
		edge("d-stepup", "no-allow", "нет", "fail"),
		edge("d-stepup", "cont-issue", "да", "branch"),
		edge("cont-issue", "end-stepup"),
		edge("born", "issue"),
		edge("issue", "epochs"),
		edge("epochs", "seal"),
		edge("seal", "ok"),
	],
);

export const signInStepUp = flow(
	"sign-in-step-up",
	"Вход",
	"Вход: второй шаг (step-up)",
	"Политика попросила ещё один фактор. Продолжение одноразовое: первая же попытка его сжигает, верная или нет, поэтому перебор кода второго фактора каждый раз требует нового первого шага.",
	[
		node("start", "start", "signIn с continuation", {
			fn: "auth.signIn",
			where: `${SIGN_IN}#const secondStep = async`,
			text: "Приложение присылает тот же вход, но с continuation из ответа step-up-required и ответом второго фактора.",
			input: "{ tenant, device, factor (второй), response, continuation }",
		}),
		node("consume", "step", "Погасить продолжение", {
			fn: "tokens.consume('sign-in-continuation')",
			where: `${SIGN_IN}#const spent = await tokens.consume`,
			text: "Атомарное взятие записи из хранилища токенов. Запись исчезает при первой попытке, неважно чем она кончится.",
			jump: { flow: "tokens", node: "c-start" },
			codes: ["invalid-token"],
		}),
		node("bad-token", "end-fail", "invalid-token", {
			text: "Продолжения нет: не найдено, истекло, чужая цель, уже использовано или это не текст нужной длины.",
			codes: ["invalid-token"],
		}),
		node("d-bind", "decision", "Запись целая и привязана верно?", {
			text: "Тенант, устройство и id фактора совпадают с записанными; в записи есть субъект, доказательства (restoreProof перепроверяет claims), исход identity и список вытесненных.",
		}),
		node("refuse-bind", "end-fail", "invalid-proof", {
			text: "Запись не подходит к запросу. Продолжение уже сожжено.",
			audit: "signin.continue, reason: forbidden",
			codes: ["invalid-proof"],
		}),
		node("verify2", "step", "Второй фактор проверяет ответ", {
			fn: "verifyProof",
			where: `${PROOF}#export async function verifyProof`,
			text: "Те же правила, что на первом шаге.",
			audit: "proof.verify",
			codes: ["invalid-proof"],
		}),
		node("bad-proof2", "end-fail", "invalid-proof", {
			text: "Второй фактор отклонён. Продолжение сожжено, начинайте с первого шага.",
			codes: ["invalid-proof"],
		}),
		node("owner", "port", "Чей это второй фактор?", {
			fn: "IdentityStore.findSubject",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.findSubject(tenant, provider, externalId)",
			text: "Только поиск, ничего не создаётся: если идентичность второго фактора не привязана ни к кому, субъекта не появляется.",
		}),
		node("d-owner", "decision", "Это тот же субъект?", {
			text: "Нельзя сложить факторы разных людей.",
		}),
		node("refuse-owner", "end-fail", "invalid-proof", {
			text: "Второй фактор принадлежит другому субъекту или никому.",
			audit: "signin.continue, reason: not-owner",
			codes: ["invalid-proof"],
		}),
		node("conclude", "jump", "Решение по входу с двумя доказательствами", {
			fn: "conclude",
			text: "Политика видит оба доказательства и решает снова: allow, deny или ещё один (другой) фактор. Тот же путь, что на первом шаге.",
			jump: { flow: "sign-in", node: "conclude" },
		}),
	],
	[
		edge("start", "consume"),
		edge("consume", "bad-token", "нет записи", "fail"),
		edge("consume", "d-bind"),
		edge("d-bind", "refuse-bind", "нет", "fail"),
		edge("d-bind", "verify2", "да", "branch"),
		edge("verify2", "bad-proof2", "отказ", "fail"),
		edge("verify2", "owner"),
		edge("owner", "d-owner"),
		edge("d-owner", "refuse-owner", "нет", "fail"),
		edge("d-owner", "conclude", "да", "branch"),
	],
);
