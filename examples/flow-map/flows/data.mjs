import { edge, flow, node } from "./dsl.mjs";

const TOKENS = "packages/core/src/tokens/tokens.ts";
const TOKEN_STORE = "packages/core/src/tokens/token-store.ts";
const MUTATE = "packages/core/src/identity/mutate-identity.ts";
const IDENTITY_STORE = "packages/core/src/identity/identity-store.ts";
const EPOCH_STORE = "packages/core/src/session-tokens/epoch-store.ts";
const SEALER = "packages/core/src/sealer.ts";

export const identity = flow(
	"identity",
	"Данные",
	"Изменение идентичности",
	"Удаление субъекта и подтверждение почты. Оба пути отзывают сессии затронутых субъектов, поэтому вытесненный или удалённый человек теряет доступ сразу.",
	[
		node("start", "start", "mutateIdentity(tenant, subject, change)", {
			fn: "auth.mutateIdentity",
			where: `${MUTATE}#export function createMutateIdentity`,
			input:
				"tenant, subject, { type: delete } | { type: confirm-email, proof }",
			output: "Result<{ affectedSubjects }>",
		}),
		node("d-text", "decision", "tenant и subject можно хранить?", {
			fn: "isStorableText",
			text: "Пустые строки, управляющие символы и одиночные суррогаты отвергаются до хранилищ.",
		}),
		node("bad-request", "end-fail", "invalid-request", {
			codes: ["invalid-request"],
			audit: "identity.mutate (malformed), tenant и subject пустые",
		}),
		node("d-type", "decision", "Какое изменение?", {}),
		node("revoke-user", "port", "Отозвать человека", {
			fn: "revokeUser → EpochStore.revoke",
			where: `${EPOCH_STORE}#export type EpochStore`,
			port: "EpochStore.revoke(userKey)",
			text: "Сначала отзыв, потом удаление: между ними нет окна с живой сессией удаляемого.",
		}),
		node("delete", "port", "Удалить субъекта", {
			fn: "IdentityStore.deleteSubject",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.deleteSubject(tenant, subjectId)",
			text: "Удаляет все идентичности субъекта этого тенанта. Чужой тенант не затрагивается. Возвращает false, если такого нет.",
		}),
		node("d-deleted", "decision", "Субъект был?", {}),
		node("no-subject", "end-fail", "no-subject", {
			codes: ["no-subject"],
			audit: "identity.mutate, reason: not-found",
		}),
		node("deleted", "end-ok", "affectedSubjects: [subject]", {
			audit: "identity.mutate, reason: deleted",
		}),
		node("d-proof", "decision", "Доказательство выдано ядром?", {
			text: "Проверка по реестру чеканки: подделанный объект не пройдёт.",
		}),
		node("no-proof", "end-fail", "no-proof", {
			codes: ["no-proof"],
			audit: "identity.mutate, reason: no-proof",
		}),
		node("d-verified", "decision", "Почта подтверждена?", {}),
		node("forbidden", "end-fail", "forbidden", {
			codes: ["forbidden"],
			audit: "identity.mutate, reason: unverified | not-owner",
		}),
		node("owner", "port", "Владелец подтверждённой почты", {
			fn: "IdentityStore.findSubjectByVerifiedEmail",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.findSubjectByVerifiedEmail(tenant, email)",
		}),
		node("d-owner", "decision", "Владелец это subject?", {
			text: "Подтвердить почту за другого нельзя.",
		}),
		node("claimants", "port", "Кто претендовал без подтверждения", {
			fn: "IdentityStore.findSubjectsByUnverifiedEmail",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.findSubjectsByUnverifiedEmail(tenant, email)",
		}),
		node("revoke-early", "port", "Отозвать претендентов", {
			fn: "revokeUser",
			port: "EpochStore.revoke(userKey) для каждого",
			text: "До снятия претензий: захватчик теряет сессии прежде, чем исчезнут его претензии.",
		}),
		node("remove", "port", "Снять претензии", {
			fn: "IdentityStore.removeUnverifiedEmailClaims",
			where: `${IDENTITY_STORE}#export type IdentityStore`,
			port: "IdentityStore.removeUnverifiedEmailClaims(tenant, email, keep)",
			text: "Одной операцией: снимает неподтверждённые претензии на адрес у всех, кроме владельца и subject, помечает вытесненными (evicted_at) субъектов, оставшихся без идентичностей, и возвращает затронутых. Субъект не удаляется: данные приложения, ссылающиеся на него, остаются, а войти в него больше нельзя.",
		}),
		node("revoke-late", "port", "Отозвать опоздавших", {
			fn: "revokeUser",
			port: "EpochStore.revoke(userKey) для тех, кто появился между чтением и снятием",
			text: "Закрывает гонку: претендент мог появиться после первого чтения.",
		}),
		node("confirmed", "end-ok", "affectedSubjects: вытесненные", {
			audit: "identity.mutate, reason: email-confirmed",
		}),
	],
	[
		edge("start", "d-text"),
		edge("d-text", "bad-request", "нет", "fail"),
		edge("d-text", "d-type", "да", "branch"),
		edge("d-type", "revoke-user", "delete", "branch"),
		edge("revoke-user", "delete"),
		edge("delete", "d-deleted"),
		edge("d-deleted", "no-subject", "нет", "fail"),
		edge("d-deleted", "deleted", "да", "branch"),
		edge("d-type", "d-proof", "confirm-email", "branch"),
		edge("d-proof", "no-proof", "нет", "fail"),
		edge("d-proof", "d-verified", "да", "branch"),
		edge("d-verified", "forbidden", "нет", "fail"),
		edge("d-verified", "owner", "да", "branch"),
		edge("owner", "d-owner"),
		edge("d-owner", "forbidden", "нет", "fail"),
		edge("d-owner", "claimants", "да", "branch"),
		edge("claimants", "revoke-early"),
		edge("revoke-early", "remove"),
		edge("remove", "revoke-late"),
		edge("revoke-late", "confirmed"),
	],
);

export const tokens = flow(
	"tokens",
	"Данные",
	"Одноразовые токены",
	"Секрет для ссылки из письма, продолжения step-up и т. п. Хранится только хэш; погасить можно один раз, только для той цели, для которой выдан, и до истечения.",
	[
		node("i-start", "start", "tokens.issue(input)", {
			fn: "auth.tokens.issue",
			where: `${TOKENS}#async issue(input)`,
			input: "{ purpose, payload?, timeToLive: Duration }",
			output: "секрет (строка)",
		}),
		node("i-duration", "decision", "timeToLive выдан defineDuration?", {
			text: "Число сюда не пройдёт по типам; обход типов в JS даёт TypeError (значение не прошло проверку компилятора).",
			throws: "TypeError",
		}),
		node("i-throw", "end-fail", "TypeError", { codes: ["TypeError"] }),
		node("i-secret", "step", "Случайный секрет и его хэш", {
			fn: "generateSecret, hashSecret",
			text: "В хранилище уходит только SHA-256 секрета.",
		}),
		node("i-put", "port", "Положить запись", {
			fn: "TokenStore.put",
			where: `${TOKEN_STORE}#export type TokenStore`,
			port: "TokenStore.put(hash, { purpose, payload, expiresAt })",
			text: "Хранилище без места отвечает ошибкой переполнения (политика: отказать новому, не вытеснять живые).",
		}),
		node("i-full", "end-fail", "переполнение хранилища", {
			text: "Исключение пробрасывается, в аудит пишется отказ с причиной capacity.",
			audit: "token.issue, refusal, capacity",
			throws: "StoreFullError",
		}),
		node("i-audit", "step", "Запись в аудит", {
			audit: "token.issue (success)",
		}),
		node("i-ok", "end-ok", "Секрет выдан", {
			text: "Секрет показывают человеку один раз (например, в ссылке).",
		}),
		node("c-start", "start", "tokens.consume(token, purpose)", {
			fn: "auth.tokens.consume",
			where: `${TOKENS}#async consume(token, purpose)`,
			input: "секрет, ожидаемая цель",
			output: "Result<payload>",
		}),
		node("c-length", "decision", "Длина секрета верна?", {
			text: "Дешёвая отсечка мусора до обращения к хранилищу.",
		}),
		node("c-take", "port", "Забрать запись", {
			fn: "TokenStore.take",
			where: `${TOKEN_STORE}#export type TokenStore`,
			port: "TokenStore.take(hash)",
			text: "Атомарно удаляет и возвращает запись: из любого числа параллельных take запись достаётся одному. Postgres: delete returning; Redis: Lua; память: одна синхронная операция.",
		}),
		node("c-found", "decision", "Запись была?", {}),
		node("c-purpose", "decision", "Цель совпала?", {
			text: "Токен, предъявленный не для своей цели, сожжён (take уже удалил запись).",
		}),
		node("c-expiry", "decision", "Не истёк?", {
			text: "Срок проверяет вызывающий (ядро), а не хранилище: TTL хранилища только сборка мусора.",
		}),
		node("c-refuse", "end-fail", "invalid-token", {
			text: "Одинаковый ответ на любую причину. Причины в аудите: malformed, not-found, wrong-purpose, expired.",
			codes: ["invalid-token"],
			audit: "token.consume (refusal)",
		}),
		node("c-audit", "step", "Запись в аудит", {
			text: "До выдачи payload: если хук бросит, погашение провалится, а токен уже потрачен.",
			audit: "token.consume (success, consumed)",
		}),
		node("c-ok", "end-ok", "payload", {
			output: "Record<string, string>",
		}),
	],
	[
		edge("i-start", "i-duration"),
		edge("i-duration", "i-throw", "нет", "fail"),
		edge("i-duration", "i-secret", "да", "branch"),
		edge("i-secret", "i-put"),
		edge("i-put", "i-full", "нет места", "fail"),
		edge("i-put", "i-audit"),
		edge("i-audit", "i-ok"),
		edge("c-start", "c-length"),
		edge("c-length", "c-refuse", "нет", "fail"),
		edge("c-length", "c-take", "да", "branch"),
		edge("c-take", "c-found"),
		edge("c-found", "c-refuse", "нет", "fail"),
		edge("c-found", "c-purpose", "да", "branch"),
		edge("c-purpose", "c-refuse", "нет", "fail"),
		edge("c-purpose", "c-expiry", "да", "branch"),
		edge("c-expiry", "c-refuse", "истёк", "fail"),
		edge("c-expiry", "c-audit", "да", "branch"),
		edge("c-audit", "c-ok"),
	],
);

export const emailLink = flow(
	"email-link",
	"Данные",
	"Фактор: ссылка из письма",
	"Пример фактора-плагина. Два вызова: выдать ссылку (challenge) и проверить её при входе (verify). Доставка письма не в запросе: приложение передаёт её в outbox.",
	[
		node("ch-start", "start", "emailLink.challenge(email)", {
			fn: "emailLink.challenge",
			where:
				"packages/factor-email-link/src/email-link.ts#async challenge(email)",
			text: "Приложение обычно ставит перед ним счётчик (meter) по адресу.",
		}),
		node("ch-canon", "decision", "Адрес приемлем?", {
			fn: "canonicalizeEmail",
			where:
				"packages/core/src/identity/canonical-email.ts#export const canonicalizeEmail",
			text: "NFKC, регистр локальной части, домен через разбор URL (UTS #46). Кавычки, комментарии, слишком длинные части, управляющие символы и пробелы отвергаются.",
		}),
		node("ch-bad", "end-fail", "invalid-email", { codes: ["invalid-email"] }),
		node("ch-issue", "jump", "Выдать токен", {
			fn: "tokens.issue(email-link)",
			text: "payload { email: канонический адрес }.",
			jump: { flow: "tokens", node: "i-start" },
		}),
		node("ch-deliver", "step", "Отдать письмо приложению", {
			fn: "options.deliver({ email, token })",
			text: "Колбэк приложения. Держите его коротким: ставьте письмо в outbox, а не зовите почтовый сервис внутри запроса. Исключение дойдёт до вызывающего.",
			jump: { flow: "outbox", node: "e-start" },
		}),
		node("ch-ok", "end-ok", "Ссылка отправлена"),
		node("v-start", "start", "factor.verify(response)", {
			fn: "emailLink.factor.verify",
			where:
				"packages/factor-email-link/src/email-link.ts#async verify(response)",
			text: "Вызывается из verifyProof при входе. response это токен из ссылки.",
		}),
		node("v-string", "decision", "response это строка?", {}),
		node("v-bad", "end-fail", "invalid-token", { codes: ["invalid-token"] }),
		node("v-consume", "jump", "Погасить токен", {
			fn: "tokens.consume(email-link)",
			jump: { flow: "tokens", node: "c-start" },
		}),
		node("v-email", "decision", "В payload есть email?", {}),
		node("v-claims", "end-ok", "Claims почты", {
			output:
				"{ provider: email, externalId: email, email, emailVerified: true }",
			text: "Идут в verifyProof, который проверит их по закрытой форме и создаст Proof.",
		}),
	],
	[
		edge("ch-start", "ch-canon"),
		edge("ch-canon", "ch-bad", "нет", "fail"),
		edge("ch-canon", "ch-issue", "да", "branch"),
		edge("ch-issue", "ch-deliver"),
		edge("ch-deliver", "ch-ok"),
		edge("v-start", "v-string"),
		edge("v-string", "v-bad", "нет", "fail"),
		edge("v-string", "v-consume", "да", "branch"),
		edge("v-consume", "v-bad", "отказ", "fail"),
		edge("v-consume", "v-email"),
		edge("v-email", "v-bad", "нет", "fail"),
		edge("v-email", "v-claims", "да", "branch"),
	],
);

export const sealer = flow(
	"sealer",
	"Данные",
	"Запечатывание",
	"Зашифрованные, подписанные, привязанные к цели значения без состояния на сервере: токены сессий и агентов, OAuth state. В отличие от токенов, печать не одноразовая.",
	[
		node("s-start", "start", "sealer.seal(input)", {
			fn: "auth.sealer.seal",
			where: `${SEALER}#async seal(input)`,
			input: "{ purpose, payload?, timeToLive: Duration }",
			output: "«версия.base64url»",
		}),
		node("s-duration", "decision", "timeToLive выдан defineDuration?", {
			throws: "TypeError",
		}),
		node("s-throw", "end-fail", "TypeError", { codes: ["TypeError"] }),
		node("s-key", "step", "Ключ сообщения", {
			text: "HKDF от текущего секрета (первого в списке), случайной соли и цели. Другая цель или соль дают другой ключ.",
		}),
		node("s-encrypt", "step", "Шифрование AES-GCM", {
			text: "Случайный вектор инициализации; внутри { payload, expiresAt }. Соль, вектор и шифртекст в base64url, спереди номер версии секрета.",
		}),
		node("s-ok", "end-ok", "Запечатанное значение"),
		node("u-start", "start", "sealer.unseal(sealed, purpose)", {
			fn: "auth.sealer.unseal",
			where: `${SEALER}#async unseal(sealed, purpose)`,
			input: "значение, ожидаемая цель",
			output: "Result<payload>",
		}),
		node("u-parse", "decision", "Формат «версия.тело» верен?", {
			text: "Версия: цифры без ведущих нулей, ограниченная длина.",
		}),
		node("u-version", "decision", "Версия секрета известна?", {
			text: "Секрет можно ротировать: новый ставят первым, старый оставляют, пока не истекут запечатанные им значения.",
		}),
		node("u-decrypt", "decision", "Расшифровалось?", {
			text: "Неверная цель, чужой секрет или правка значения дают одну и ту же ошибку.",
		}),
		node("u-expiry", "decision", "Не истекло?", {}),
		node("u-refuse", "end-fail", "invalid-seal", {
			codes: ["invalid-seal"],
			audit:
				"seal.unseal (refusal): malformed | unknown-version | undecryptable | expired",
		}),
		node("u-ok", "end-ok", "payload"),
	],
	[
		edge("s-start", "s-duration"),
		edge("s-duration", "s-throw", "нет", "fail"),
		edge("s-duration", "s-key", "да", "branch"),
		edge("s-key", "s-encrypt"),
		edge("s-encrypt", "s-ok"),
		edge("u-start", "u-parse"),
		edge("u-parse", "u-refuse", "нет", "fail"),
		edge("u-parse", "u-version", "да", "branch"),
		edge("u-version", "u-refuse", "нет", "fail"),
		edge("u-version", "u-decrypt", "да", "branch"),
		edge("u-decrypt", "u-refuse", "нет", "fail"),
		edge("u-decrypt", "u-expiry", "да", "branch"),
		edge("u-expiry", "u-refuse", "истекло", "fail"),
		edge("u-expiry", "u-ok", "да", "branch"),
	],
);
