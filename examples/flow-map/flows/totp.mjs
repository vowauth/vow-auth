import { edge, flow, node } from "./dsl.mjs";

const TOTP = "packages/factor-totp/src/totp.ts";
const TOTP_STORE = "packages/factor-totp/src/store.ts";

export const totpEnroll = flow(
	"totp-enroll",
	"Вход",
	"TOTP: подключение",
	"Человек уже вошёл и подключает приложение-аутентификатор в два шага: сначала секрет, потом первый код. Пока код не введён, фактор не работает.",
	[
		node("start", "start", "totp.begin({ tenant, subject, account })", {
			fn: "totp.begin",
			where: `${TOTP}#async begin(`,
			input: "tenant, subject, account",
			output: "Result<{ secret, uri }>",
		}),
		node("exists", "decision", "Подтверждённое подключение уже есть?", {
			text: "Тогда сначала remove: так чужая сессия не подменит секрет молча. Неподтверждённое подключение заменяется новым секретом.",
		}),
		node("forbidden", "end-fail", "forbidden", { codes: ["forbidden"] }),
		node("seal", "step", "Секрет запечатан", {
			fn: "sealer.seal",
			where: "packages/core/src/sealer.ts#export type Sealer",
			text: "20 случайных байт, в запись кладётся только запечатанное значение с привязкой к tenant и subject. Время жизни задаёт приложение (secretTimeToLive).",
		}),
		node("save", "port", "Сохранить неподтверждённую запись", {
			fn: "TotpStore.save",
			where: `${TOTP_STORE}#export type TotpStore`,
			port: "TotpStore.save(tenant, subject, record)",
		}),
		node("shown", "end-ok", "Секрет и адрес для QR-кода", {
			text: "Показывается один раз. QR рисуйте у себя: адрес содержит секрет.",
		}),
		node("c-start", "start", "totp.confirm({ code })", {
			fn: "totp.confirm",
			where: `${TOTP}#async confirm(`,
		}),
		node("c-limit", "decision", "Лимит попыток", {
			text: "Шесть цифр угадываются, поэтому лимит обязателен: лимитер или явное off.",
		}),
		node("c-limited", "end-fail", "rate-limited", { codes: ["rate-limited"] }),
		node("c-check", "decision", "Код сходится в окне ±1 шаг?", {
			fn: "findStep",
			where: "packages/factor-totp/src/otp.ts#export const findStep",
			text: "HMAC-SHA-1, 6 цифр, шаг 30 с (RFC 6238). Все три кода окна считаются и сравниваются одинаково, время не выдаёт близкий.",
		}),
		node("c-bad", "end-fail", "invalid-proof", { codes: ["invalid-proof"] }),
		node("c-advance", "port", "Принять шаг один раз", {
			fn: "TotpStore.advance",
			where: `${TOTP_STORE}#export type TotpStore`,
			port: "TotpStore.advance(tenant, subject, step)",
			text: "Атомарно: шаг принимается, только если он выше последнего принятого. Код, который подтвердил подключение, войти уже не поможет.",
		}),
		node("c-codes", "step", "10 резервных кодов", {
			fn: "generateBackupCodes",
			where:
				"packages/factor-totp/src/backup-codes.ts#export const generateBackupCodes",
			text: "По 128 бит (NIST разрешает простой хэш от 112 бит). В хранилище только SHA-256, сами коды показываются один раз.",
		}),
		node("c-save", "port", "Пометить подтверждённым", {
			fn: "TotpStore.save",
			port: "TotpStore.save(tenant, subject, record)",
		}),
		node("c-ok", "end-ok", "Резервные коды"),
	],
	[
		edge("start", "exists"),
		edge("exists", "forbidden", "да", "fail"),
		edge("exists", "seal", "нет"),
		edge("seal", "save"),
		edge("save", "shown"),
		edge("c-start", "c-limit"),
		edge("c-limit", "c-limited", "выше предела", "fail"),
		edge("c-limit", "c-check", "в пределах или off"),
		edge("c-check", "c-bad", "нет", "fail"),
		edge("c-check", "c-advance", "да"),
		edge("c-advance", "c-bad", "шаг уже принят", "fail"),
		edge("c-advance", "c-codes", "принят"),
		edge("c-codes", "c-save"),
		edge("c-save", "c-ok"),
	],
);

export const totpVerify = flow(
	"totp-verify",
	"Вход",
	"TOTP: второй шаг входа",
	"Фактор работает только вторым шагом step-up. Кто это, говорит не клиент: ядро передаёт субъекта и уже пройденные доказательства, фактор возвращает утверждения первого из них.",
	[
		node("start", "start", "signIn с continuation и фактором totp", {
			fn: "totp.factor.verify",
			where: `${TOTP}#async verify(response, context)`,
			input:
				"response: { code } или { backupCode }; context: { tenant, subject, proofs }",
			output: "утверждения первого доказательства",
		}),
		node("subject", "decision", "Субъект и прошлое доказательство есть?", {
			text: "Первым шагом контекст пуст, поэтому TOTP не заменяет вход: он не знает, кто человек.",
		}),
		node("bad", "end-fail", "invalid-proof", { codes: ["invalid-proof"] }),
		node("limit", "decision", "Лимит попыток", {
			text: "Один и тот же код нельзя подбирать бесконечно, даже если каждый подбор требует полного первого шага.",
		}),
		node("limited", "end-fail", "rate-limited", { codes: ["rate-limited"] }),
		node("find", "port", "Запись человека", {
			fn: "TotpStore.find",
			port: "TotpStore.find(tenant, subject)",
			text: "Нет записи или подключение не подтверждено: тот же отказ, что и за неверный код.",
		}),
		node("kind", "decision", "Резервный код или код приложения?", {}),
		node("backup", "port", "Потратить резервный код", {
			fn: "TotpStore.spendBackupCode",
			where: `${TOTP_STORE}#export type TotpStore`,
			port: "TotpStore.spendBackupCode(tenant, subject, hash)",
			text: "Атомарно: из двух одновременных попыток с одним кодом успех у одной. Регистр, пробелы и дефисы не важны.",
		}),
		node("open", "step", "Открыть секрет и найти шаг", {
			fn: "findStep",
			text: "Печать привязана к tenant и subject: запись, скопированная к другому человеку, не открывается.",
		}),
		node("advance", "port", "Принять шаг один раз", {
			fn: "TotpStore.advance",
			port: "TotpStore.advance(tenant, subject, step)",
			text: "Повтор того же кода, и более старого, отвергается (RFC 6238: MUST NOT).",
		}),
		node("done", "jump", "Дальше ядро", {
			text: "Ядро проверяет, что личность та же, что у первого шага, и спрашивает политику.",
			jump: { flow: "sign-in-step-up", node: "start" },
		}),
	],
	[
		edge("start", "subject"),
		edge("subject", "bad", "нет", "fail"),
		edge("subject", "limit", "да"),
		edge("limit", "limited", "выше предела", "fail"),
		edge("limit", "find", "в пределах или off"),
		edge("find", "bad", "нет записи", "fail"),
		edge("find", "kind"),
		edge("kind", "backup", "резервный код"),
		edge("kind", "open", "код приложения"),
		edge("backup", "bad", "нет такого", "fail"),
		edge("backup", "done", "потрачен"),
		edge("open", "bad", "не сошёлся", "fail"),
		edge("open", "advance", "сошёлся"),
		edge("advance", "bad", "шаг уже принят", "fail"),
		edge("advance", "done", "принят"),
	],
);
