window.FLOW_DATA = {
	"groups": [
		"Обзор",
		"Вход",
		"Сессии и агенты",
		"Данные",
		"Защита",
		"Асинхронность",
		"Режим сервиса",
		"Запуск и инструменты"
	],
	"events": [
		"authorize.check",
		"delegation.grant",
		"identity.mutate",
		"identity.resolve",
		"meter.consume",
		"policy.evaluate",
		"proof.verify",
		"session.issue",
		"seal.unseal",
		"session.revoke",
		"signin.continue",
		"session.verify",
		"token.consume",
		"token.issue"
	],
	"ports": [
		"IdentityStore",
		"EpochStore",
		"TokenStore",
		"MeterStore",
		"OutboxStore"
	],
	"flows": [
		{
			"id": "map",
			"group": "Обзор",
			"title": "Карта слоёв",
			"summary": "Как устроено целиком. Приложение вызывает поверхность Auth; части ядра делают работу и через порты ходят в хранилища; адаптеры отвечают на порты. Аудит один на все части. Кликните узел, чтобы открыть его путь.",
			"nodes": [
				{
					"id": "app",
					"kind": "start",
					"title": "Ваше приложение",
					"layer": 0,
					"text": "Маршруты HTTP, фоновые задачи. Вызывает поверхность Auth напрямую или через клиент сервиса."
				},
				{
					"id": "service",
					"kind": "step",
					"title": "Сервис по сети",
					"layer": 1,
					"text": "Клиент и обработчик: те же формы ответов, сбой сети всегда отказ.",
					"jump": {
						"flow": "service-server",
						"node": "start"
					}
				},
				{
					"id": "surface",
					"kind": "step",
					"title": "Auth (createAuth)",
					"layer": 2,
					"fn": "createAuth",
					"text": "Единственная публичная точка входа в ядро.",
					"jump": {
						"flow": "startup",
						"node": "start"
					},
					"source": {
						"file": "packages/core/src/auth.ts",
						"line": 82
					}
				},
				{
					"id": "s-signin",
					"kind": "step",
					"title": "signIn",
					"layer": 3,
					"text": "Единственная дорога к сессии.",
					"jump": {
						"flow": "sign-in",
						"node": "start"
					}
				},
				{
					"id": "s-sessions",
					"kind": "step",
					"title": "sessions.verify / revoke",
					"layer": 3,
					"jump": {
						"flow": "session-verify",
						"node": "start"
					}
				},
				{
					"id": "s-agents",
					"kind": "step",
					"title": "agents.delegate / verify",
					"layer": 3,
					"jump": {
						"flow": "agent-delegate",
						"node": "start"
					}
				},
				{
					"id": "s-tokens",
					"kind": "step",
					"title": "tokens",
					"layer": 3,
					"jump": {
						"flow": "tokens",
						"node": "i-start"
					}
				},
				{
					"id": "s-meter",
					"kind": "step",
					"title": "meter",
					"layer": 3,
					"jump": {
						"flow": "meter",
						"node": "start"
					}
				},
				{
					"id": "s-sealer",
					"kind": "step",
					"title": "sealer",
					"layer": 3,
					"jump": {
						"flow": "sealer",
						"node": "s-start"
					}
				},
				{
					"id": "s-mutate",
					"kind": "step",
					"title": "mutateIdentity",
					"layer": 3,
					"jump": {
						"flow": "identity",
						"node": "start"
					}
				},
				{
					"id": "p-proof",
					"kind": "step",
					"title": "verifyProof",
					"layer": 4,
					"text": "Фактор плагина → Proof.",
					"source": {
						"file": "packages/core/src/proof.ts",
						"line": 138
					}
				},
				{
					"id": "p-resolve",
					"kind": "step",
					"title": "resolveIdentity",
					"layer": 4,
					"source": {
						"file": "packages/core/src/identity/resolve-identity.ts",
						"line": 46
					}
				},
				{
					"id": "p-policy",
					"kind": "step",
					"title": "evaluatePolicy / issueSession",
					"layer": 4,
					"text": "Политика решает; только решение allow превращается в сессию.",
					"source": {
						"file": "packages/core/src/decision.ts",
						"line": 130
					}
				},
				{
					"id": "p-session-tokens",
					"kind": "step",
					"title": "sessionTokens",
					"layer": 4,
					"text": "Цепочка уровней с штампами; выпуск, проверка, отзыв, агенты.",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 282
					}
				},
				{
					"id": "p-sealer",
					"kind": "step",
					"title": "sealer",
					"layer": 5,
					"source": {
						"file": "packages/core/src/sealer.ts",
						"line": 216
					}
				},
				{
					"id": "p-tokens",
					"kind": "step",
					"title": "tokens",
					"layer": 4,
					"source": {
						"file": "packages/core/src/tokens/tokens.ts",
						"line": 52
					}
				},
				{
					"id": "p-meter",
					"kind": "step",
					"title": "meter",
					"layer": 4,
					"source": {
						"file": "packages/core/src/meter/meter.ts",
						"line": 128
					}
				},
				{
					"id": "p-mutate",
					"kind": "step",
					"title": "mutateIdentity",
					"layer": 4,
					"source": {
						"file": "packages/core/src/identity/mutate-identity.ts",
						"line": 77
					}
				},
				{
					"id": "p-outbox",
					"kind": "step",
					"title": "emit / воркер outbox",
					"layer": 2,
					"text": "Живут рядом с Auth, а не внутри него: приложение зовёт emit из запроса, а воркер из планировщика.",
					"jump": {
						"flow": "outbox",
						"node": "e-start"
					},
					"source": {
						"file": "packages/core/src/outbox/emit.ts",
						"line": 58
					}
				},
				{
					"id": "port-identity",
					"kind": "port",
					"title": "IdentityStore",
					"layer": 6,
					"text": "Субъекты и их идентичности. Атомарно и «первый выигрывает».",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "port-epoch",
					"kind": "port",
					"title": "EpochStore",
					"layer": 6,
					"text": "Штампы отзыва и единственные часы токенов.",
					"source": {
						"file": "packages/core/src/session-tokens/epoch-store.ts",
						"line": 32
					}
				},
				{
					"id": "port-token",
					"kind": "port",
					"title": "TokenStore",
					"layer": 6,
					"text": "Одноразовые записи: атомарный take.",
					"source": {
						"file": "packages/core/src/tokens/token-store.ts",
						"line": 24
					}
				},
				{
					"id": "port-meter",
					"kind": "port",
					"title": "MeterStore",
					"layer": 6,
					"text": "Счётчики скользящего окна.",
					"source": {
						"file": "packages/core/src/meter/meter-store.ts",
						"line": 21
					}
				},
				{
					"id": "port-outbox",
					"kind": "port",
					"title": "OutboxStore",
					"layer": 6,
					"text": "События наружу: append, claim с арендой, complete, release, bury.",
					"source": {
						"file": "packages/core/src/outbox/outbox-store.ts",
						"line": 34
					}
				},
				{
					"id": "memory",
					"kind": "adapter",
					"title": "adapter-memory",
					"layer": 7,
					"text": "Все пять портов, для тестов и разработки на одном экземпляре.",
					"source": {
						"file": "packages/adapter-memory/src/memory-identity-store.ts",
						"line": 26
					}
				},
				{
					"id": "redis",
					"kind": "adapter",
					"title": "adapter-redis",
					"layer": 7,
					"text": "Эпохи и счётчик (Lua, время сервера Redis).",
					"source": {
						"file": "packages/adapter-redis/src/redis-epoch-store.ts",
						"line": 44
					}
				},
				{
					"id": "postgres",
					"kind": "adapter",
					"title": "adapter-postgres",
					"layer": 7,
					"text": "Идентичности, токены, outbox. Свой исполнитель запросов.",
					"source": {
						"file": "packages/adapter-postgres/src/postgres-identity-store.ts",
						"line": 67
					}
				},
				{
					"id": "audit",
					"kind": "step",
					"title": "Приёмник аудита",
					"layer": 5,
					"text": "Обязателен и общий для всех частей. Записи: событие, исход, причина, тенант, субъект, детали; секретов нет. Ограничивающие решения пишутся после, расширяющие до.",
					"source": {
						"file": "packages/core/src/audit.ts",
						"line": 95
					}
				}
			],
			"edges": [
				{
					"from": "app",
					"to": "surface",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "app",
					"to": "service",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "service",
					"to": "surface",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "app",
					"to": "p-outbox",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-outbox",
					"to": "port-outbox",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-signin",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-sessions",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-agents",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-meter",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-sealer",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "surface",
					"to": "s-mutate",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-signin",
					"to": "p-proof",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-signin",
					"to": "p-resolve",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-signin",
					"to": "p-policy",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-signin",
					"to": "p-session-tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-sessions",
					"to": "p-session-tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-agents",
					"to": "p-session-tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-tokens",
					"to": "p-tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-meter",
					"to": "p-meter",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-sealer",
					"to": "p-sealer",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-mutate",
					"to": "p-mutate",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-resolve",
					"to": "port-identity",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-mutate",
					"to": "port-identity",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-mutate",
					"to": "port-epoch",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-session-tokens",
					"to": "p-sealer",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-session-tokens",
					"to": "port-epoch",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-tokens",
					"to": "port-token",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-meter",
					"to": "port-meter",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-identity",
					"to": "memory",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-identity",
					"to": "postgres",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-epoch",
					"to": "memory",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-epoch",
					"to": "redis",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-token",
					"to": "memory",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-token",
					"to": "postgres",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-meter",
					"to": "memory",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-meter",
					"to": "redis",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-outbox",
					"to": "memory",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "port-outbox",
					"to": "postgres",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "p-session-tokens",
					"to": "audit",
					"label": "report",
					"kind": "branch"
				}
			]
		},
		{
			"id": "sign-in",
			"group": "Вход",
			"title": "Вход: первый шаг",
			"summary": "Единственная дорога к сессии. Любой фактор, нынешний и будущий, идёт по ней: проверка доказательства, определение субъекта, политика, выдача токена. Сессию нельзя получить, минуя этот путь.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "signIn(request)",
					"fn": "auth.signIn",
					"text": "Вход в ядро. Приложение передаёт тенант, устройство, фактор (плагин) и ответ, который человек прислал этому фактору.",
					"input": "{ tenant, device, factor, response, continuation? }",
					"output": "Result<SignedIn, SignInRefusal>",
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 173
					}
				},
				{
					"id": "text",
					"kind": "decision",
					"title": "Имена можно хранить?",
					"fn": "isStorableText",
					"text": "tenant, device и continuation должны быть непустым текстом без управляющих символов (NUL) и одиночных суррогатов. Иначе хранилище (Postgres) не удержит значение. Проверка до любого обращения к хранилищу.",
					"codes": [
						"invalid-request"
					],
					"source": {
						"file": "packages/core/src/shared/is-storable-text.ts",
						"line": 11
					}
				},
				{
					"id": "bad-request",
					"kind": "end-fail",
					"title": "invalid-request",
					"text": "Запрос отвергнут на границе, ни одно хранилище не вызывалось.",
					"codes": [
						"invalid-request"
					]
				},
				{
					"id": "cont",
					"kind": "decision",
					"title": "Есть continuation?",
					"fn": "secondStep / firstStep",
					"text": "continuation приходит только на втором шаге step-up. Без него идёт первый шаг.",
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 415
					}
				},
				{
					"id": "second",
					"kind": "jump",
					"title": "Второй шаг step-up",
					"text": "Продолжение входа после второго фактора.",
					"jump": {
						"flow": "sign-in-step-up",
						"node": "start"
					}
				},
				{
					"id": "verify",
					"kind": "step",
					"title": "Фактор проверяет ответ",
					"fn": "verifyProof",
					"text": "Вызывает factor.verify(response) (код плагина, исключение считается отказом), проверяет claims по закрытой форме (parseClaims: provider, externalId, email, emailVerified; email канонизируется), пишет в аудит и чеканит Proof. Proof создаёт только эта функция.",
					"input": "factor, response",
					"output": "Proof { factor, strength, verifiedAt, claims }",
					"audit": "proof.verify (успех и каждый отказ)",
					"codes": [
						"invalid-proof"
					],
					"source": {
						"file": "packages/core/src/proof.ts",
						"line": 138
					}
				},
				{
					"id": "bad-proof",
					"kind": "end-fail",
					"title": "invalid-proof",
					"text": "Фактор отклонил ответ, бросил исключение, вернул claims непонятной формы или с недопустимой почтой. Причину знает только аудит (factor-rejected, factor-error, invalid-claims, invalid-email).",
					"codes": [
						"invalid-proof"
					],
					"audit": "proof.verify, reason: factor-rejected | factor-error | invalid-claims | invalid-email"
				},
				{
					"id": "resolve",
					"kind": "step",
					"title": "Какой это субъект?",
					"fn": "resolveIdentity",
					"text": "Сопоставляет доказательство с субъектом тенанта: уже знакомая идентичность, привязка к владельцу подтверждённой почты или новый субъект.",
					"input": "tenant, Proof",
					"output": "{ subjectId, outcome: existing | linked | created }",
					"audit": "identity.resolve",
					"source": {
						"file": "packages/core/src/identity/resolve-identity.ts",
						"line": 46
					}
				},
				{
					"id": "find",
					"kind": "port",
					"title": "Идентичность уже известна?",
					"fn": "IdentityStore.findSubject",
					"port": "IdentityStore.findSubject(tenant, provider, externalId)",
					"text": "Поиск по паре (provider, externalId) внутри тенанта.",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "d-found",
					"kind": "decision",
					"title": "Нашли?"
				},
				{
					"id": "d-verified",
					"kind": "decision",
					"title": "Почта подтверждена?",
					"text": "Привязывать по почте можно только если фактор подтвердил владение ею (A3). Неподтверждённая почта никогда не линкует."
				},
				{
					"id": "owner",
					"kind": "port",
					"title": "Кто владеет подтверждённой почтой?",
					"fn": "IdentityStore.findSubjectByVerifiedEmail",
					"port": "IdentityStore.findSubjectByVerifiedEmail(tenant, email)",
					"text": "Владелец: самая ранняя идентичность, подтвердившая этот адрес.",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "d-owner",
					"kind": "decision",
					"title": "Есть владелец?"
				},
				{
					"id": "link",
					"kind": "port",
					"title": "Привязать к владельцу",
					"fn": "IdentityStore.linkIdentity",
					"port": "IdentityStore.linkIdentity(tenant, subjectId, identity)",
					"text": "Атомарно и «первый выигрывает»: возвращает субъекта, которому принадлежит идентичность после вызова.",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "create",
					"kind": "port",
					"title": "Создать субъекта",
					"fn": "IdentityStore.createSubject",
					"port": "IdentityStore.createSubject(tenant, identity)",
					"text": "Атомарно и «первый выигрывает». Если параллельный вход успел раньше, возвращается его субъект (isNew: false, исход existing).",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "resolved",
					"kind": "step",
					"title": "Субъект определён",
					"text": "Исход existing, linked или created записан в аудит. Дальше решает политика.",
					"output": "{ subjectId, outcome }",
					"audit": "identity.resolve (success)"
				},
				{
					"id": "d-confirm",
					"kind": "decision",
					"title": "emailVerified?",
					"text": "Если фактор подтвердил почту, ядро подтверждает её для субъекта и убирает чужие неподтверждённые претензии на этот адрес."
				},
				{
					"id": "confirm",
					"kind": "jump",
					"title": "Подтвердить почту",
					"fn": "mutateIdentity(confirm-email)",
					"text": "Вытесняет неподтверждённые претензии, отзывает сессии вытесненных субъектов.",
					"jump": {
						"flow": "identity",
						"node": "d-verified"
					}
				},
				{
					"id": "conclude",
					"kind": "step",
					"title": "Решение по входу",
					"fn": "conclude",
					"text": "Общий финал обоих шагов входа. Спрашивает политику, потом выдаёт сессию или просит ещё фактор.",
					"input": "subjectId, proofs (все пройденные доказательства), outcome, email, evicted",
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 206
					}
				},
				{
					"id": "policy",
					"kind": "step",
					"title": "Политика решает",
					"fn": "evaluatePolicy",
					"text": "Вызывает policy({ subject, tenant, proof, proofs }). Разрешением считается только точная строка «allow»; requireFactor(id) просит ещё фактор; всё остальное, включая исключение, это отказ. Решение пишется в аудит; allow записывается до выдачи.",
					"audit": "policy.evaluate",
					"codes": [
						"no-allow"
					],
					"source": {
						"file": "packages/core/src/decision.ts",
						"line": 130
					}
				},
				{
					"id": "d-verdict",
					"kind": "decision",
					"title": "Что ответила политика?",
					"fn": "judge",
					"source": {
						"file": "packages/core/src/decision.ts",
						"line": 95
					}
				},
				{
					"id": "d-stepup",
					"kind": "decision",
					"title": "Можно просить фактор?",
					"text": "Нужны оба условия: в createAuth задан stepUpTimeToLiveMilliseconds и этот фактор ещё не пройден в этом входе. Иначе step-up превращается в отказ.",
					"codes": [
						"no-allow"
					]
				},
				{
					"id": "cont-issue",
					"kind": "step",
					"title": "Записать продолжение",
					"fn": "tokens.issue (sign-in-continuation)",
					"text": "Одноразовая запись в хранилище токенов: тенант, устройство, субъект, нужный фактор, доказательства шага 1, исход, вытесненные. Срок stepUpTimeToLiveMilliseconds.",
					"jump": {
						"flow": "tokens",
						"node": "i-put"
					},
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 230
					}
				},
				{
					"id": "end-stepup",
					"kind": "end-wait",
					"title": "step-up-required",
					"text": "Сессия не выдана. Ошибка несёт { code: 'step-up-required', factor, continuation }: приложение просит человека пройти второй фактор и вызывает signIn с continuation. ok остаётся false.",
					"output": "{ code: step-up-required, factor, continuation }",
					"jump": {
						"flow": "sign-in-step-up",
						"node": "start"
					}
				},
				{
					"id": "no-allow",
					"kind": "end-fail",
					"title": "no-allow",
					"text": "Политика не разрешила (или step-up невозможен). Токен не выдан.",
					"codes": [
						"no-allow"
					],
					"audit": "policy.evaluate, reason: not-allowed | policy-error | step-up-unavailable"
				},
				{
					"id": "born",
					"kind": "step",
					"title": "Рождается сессия",
					"fn": "issueSession",
					"text": "Принимает только allow-решение, выданное evaluatePolicy (проверка по реестру чеканки, не по форме). Создаёт Session { id (случайный), subject }.",
					"codes": [
						"no-allow"
					],
					"source": {
						"file": "packages/core/src/session.ts",
						"line": 20
					}
				},
				{
					"id": "issue",
					"kind": "step",
					"title": "Токен сессии",
					"fn": "sessionTokens.issue",
					"text": "Проверяет, что срок это Duration не больше максимума; пишет session.issue в аудит (до выдачи); читает штампы эпох цепочки тенант → пользователь → устройство → сессия за один обмен с хранилищем; запечатывает цепочку, срок, методы входа и время входа.",
					"input": "Session, { tenant, device, timeToLive, methods }",
					"output": "строка-токен",
					"audit": "session.issue",
					"codes": [
						"invalid-request"
					],
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 419
					}
				},
				{
					"id": "epochs",
					"kind": "port",
					"title": "Прочитать штампы цепочки",
					"fn": "EpochStore.read",
					"port": "EpochStore.read(keys)",
					"text": "Одна атомарная операция: время хранилища и штамп каждого уровня цепочки. Штампы кладутся в токен.",
					"source": {
						"file": "packages/core/src/session-tokens/epoch-store.ts",
						"line": 32
					}
				},
				{
					"id": "seal",
					"kind": "step",
					"title": "Запечатать",
					"fn": "sealer.seal",
					"text": "AES-GCM с ключом из HKDF (секрет, соль, цель «session»). Результат «версия.base64url».",
					"jump": {
						"flow": "sealer",
						"node": "s-start"
					},
					"source": {
						"file": "packages/core/src/sealer.ts",
						"line": 272
					}
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "SignedIn",
					"text": "Сессия выдана.",
					"output": "{ token, tenant, subject, device, session, identity, email, evicted }"
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "text",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "text",
					"to": "bad-request",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "text",
					"to": "cont",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "cont",
					"to": "second",
					"label": "есть",
					"kind": "branch"
				},
				{
					"from": "cont",
					"to": "verify",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "verify",
					"to": "bad-proof",
					"label": "отказ",
					"kind": "fail"
				},
				{
					"from": "verify",
					"to": "resolve",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "resolve",
					"to": "find",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "find",
					"to": "d-found",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-found",
					"to": "resolved",
					"label": "да: existing",
					"kind": "branch"
				},
				{
					"from": "d-found",
					"to": "d-verified",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "d-verified",
					"to": "create",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "d-verified",
					"to": "owner",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "owner",
					"to": "d-owner",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-owner",
					"to": "link",
					"label": "да: linked",
					"kind": "branch"
				},
				{
					"from": "d-owner",
					"to": "create",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "link",
					"to": "resolved",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "create",
					"to": "resolved",
					"label": "created | existing",
					"kind": "ok"
				},
				{
					"from": "resolved",
					"to": "d-confirm",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-confirm",
					"to": "confirm",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-confirm",
					"to": "conclude",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "confirm",
					"to": "conclude",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "conclude",
					"to": "policy",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "policy",
					"to": "d-verdict",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-verdict",
					"to": "born",
					"label": "allow",
					"kind": "branch"
				},
				{
					"from": "d-verdict",
					"to": "d-stepup",
					"label": "requireFactor",
					"kind": "branch"
				},
				{
					"from": "d-verdict",
					"to": "no-allow",
					"label": "любое другое",
					"kind": "fail"
				},
				{
					"from": "d-stepup",
					"to": "no-allow",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-stepup",
					"to": "cont-issue",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "cont-issue",
					"to": "end-stepup",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "born",
					"to": "issue",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "issue",
					"to": "epochs",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "epochs",
					"to": "seal",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "seal",
					"to": "ok",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "sign-in-step-up",
			"group": "Вход",
			"title": "Вход: второй шаг (step-up)",
			"summary": "Политика попросила ещё один фактор. Продолжение одноразовое: первая же попытка его сжигает, верная или нет, поэтому перебор кода второго фактора каждый раз требует нового первого шага.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "signIn с continuation",
					"fn": "auth.signIn",
					"text": "Приложение присылает тот же вход, но с continuation из ответа step-up-required и ответом второго фактора.",
					"input": "{ tenant, device, factor (второй), response, continuation }",
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 347
					}
				},
				{
					"id": "consume",
					"kind": "step",
					"title": "Погасить продолжение",
					"fn": "tokens.consume('sign-in-continuation')",
					"text": "Атомарное взятие записи из хранилища токенов. Запись исчезает при первой попытке, неважно чем она кончится.",
					"jump": {
						"flow": "tokens",
						"node": "c-start"
					},
					"codes": [
						"invalid-token"
					],
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 352
					}
				},
				{
					"id": "bad-token",
					"kind": "end-fail",
					"title": "invalid-token",
					"text": "Продолжения нет: не найдено, истекло, чужая цель, уже использовано или это не текст нужной длины.",
					"codes": [
						"invalid-token"
					]
				},
				{
					"id": "d-bind",
					"kind": "decision",
					"title": "Запись целая и привязана верно?",
					"text": "Тенант, устройство и id фактора совпадают с записанными; в записи есть субъект, доказательства (restoreProof перепроверяет claims), исход identity и список вытесненных."
				},
				{
					"id": "refuse-bind",
					"kind": "end-fail",
					"title": "invalid-proof",
					"text": "Запись не подходит к запросу. Продолжение уже сожжено.",
					"audit": "signin.continue, reason: forbidden",
					"codes": [
						"invalid-proof"
					]
				},
				{
					"id": "verify2",
					"kind": "step",
					"title": "Второй фактор проверяет ответ",
					"fn": "verifyProof",
					"text": "Те же правила, что на первом шаге.",
					"audit": "proof.verify",
					"codes": [
						"invalid-proof"
					],
					"source": {
						"file": "packages/core/src/proof.ts",
						"line": 138
					}
				},
				{
					"id": "bad-proof2",
					"kind": "end-fail",
					"title": "invalid-proof",
					"text": "Второй фактор отклонён. Продолжение сожжено, начинайте с первого шага.",
					"codes": [
						"invalid-proof"
					]
				},
				{
					"id": "owner",
					"kind": "port",
					"title": "Чей это второй фактор?",
					"fn": "IdentityStore.findSubject",
					"port": "IdentityStore.findSubject(tenant, provider, externalId)",
					"text": "Только поиск, ничего не создаётся: если идентичность второго фактора не привязана ни к кому, субъекта не появляется.",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "d-owner",
					"kind": "decision",
					"title": "Это тот же субъект?",
					"text": "Нельзя сложить факторы разных людей."
				},
				{
					"id": "refuse-owner",
					"kind": "end-fail",
					"title": "invalid-proof",
					"text": "Второй фактор принадлежит другому субъекту или никому.",
					"audit": "signin.continue, reason: not-owner",
					"codes": [
						"invalid-proof"
					]
				},
				{
					"id": "conclude",
					"kind": "jump",
					"title": "Решение по входу с двумя доказательствами",
					"fn": "conclude",
					"text": "Политика видит оба доказательства и решает снова: allow, deny или ещё один (другой) фактор. Тот же путь, что на первом шаге.",
					"jump": {
						"flow": "sign-in",
						"node": "conclude"
					}
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "consume",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "consume",
					"to": "bad-token",
					"label": "нет записи",
					"kind": "fail"
				},
				{
					"from": "consume",
					"to": "d-bind",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-bind",
					"to": "refuse-bind",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-bind",
					"to": "verify2",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "verify2",
					"to": "bad-proof2",
					"label": "отказ",
					"kind": "fail"
				},
				{
					"from": "verify2",
					"to": "owner",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "owner",
					"to": "d-owner",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-owner",
					"to": "refuse-owner",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-owner",
					"to": "conclude",
					"label": "да",
					"kind": "branch"
				}
			]
		},
		{
			"id": "http-cookie",
			"group": "Вход",
			"title": "HTTP: браузер (cookie)",
			"summary": "Обработчик для страниц в браузере. Токен сессии живёт только в cookie, которую не читает скрипт, и не попадает в тело ответа. Чужой сайт не может отправить запрос, заголовок Authorization не читается вовсе.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "POST /sign-in/<фактор>",
					"fn": "createCookieHandler",
					"input": "Request (JSON, Origin, Sec-Fetch-Site, cookie)",
					"output": "Response",
					"source": {
						"file": "packages/http/src/cookie-handler.ts",
						"line": 64
					}
				},
				{
					"id": "route",
					"kind": "decision",
					"title": "Путь и метод известны?",
					"fn": "route",
					"text": "Закрытая таблица маршрутов. Неизвестный путь: 404, не тот метод: 405 с Allow.",
					"source": {
						"file": "packages/http/src/handler.ts",
						"line": 398
					}
				},
				{
					"id": "route-bad",
					"kind": "end-fail",
					"title": "404 или 405",
					"codes": [
						"404",
						"405"
					]
				},
				{
					"id": "origin",
					"kind": "decision",
					"title": "Запрос с нашей страницы?",
					"fn": "checkOrigin",
					"text": "Сначала Fetch Metadata (cross-site и none отказ), затем весь Origin (схема, хост, порт) точно по списку; Origin null никогда. Без Origin берётся Referer, а без обоих только same-origin.",
					"source": {
						"file": "packages/http/src/origin.ts",
						"line": 34
					}
				},
				{
					"id": "origin-bad",
					"kind": "end-fail",
					"title": "403 forbidden",
					"codes": [
						"forbidden"
					]
				},
				{
					"id": "json",
					"kind": "decision",
					"title": "Тело: JSON-объект в пределе?",
					"fn": "readBody",
					"text": "Content-Type только application/json (форма с чужого сайта не пройдёт без предпроверки), предел читается по потоку, а не по заголовку.",
					"source": {
						"file": "packages/http/src/handler.ts",
						"line": 143
					}
				},
				{
					"id": "json-bad",
					"kind": "end-fail",
					"title": "400, 413 или 415",
					"codes": [
						"400",
						"413",
						"415"
					]
				},
				{
					"id": "limit",
					"kind": "decision",
					"title": "Лимит попыток",
					"fn": "applyLimit",
					"text": "limit обязателен: лимитер или явное off. Забытое значение останавливает создание обработчика.",
					"source": {
						"file": "packages/http/src/handler.ts",
						"line": 275
					}
				},
				{
					"id": "limit-bad",
					"kind": "end-fail",
					"title": "429 и Retry-After",
					"codes": [
						"rate-limited"
					]
				},
				{
					"id": "device",
					"kind": "step",
					"title": "Устройство браузера",
					"fn": "deviceFor",
					"text": "Запечатанная cookie __Host-vow-device (случайный id, цель device). Подделанная или чужая печать не доверяется, выдаётся новое устройство.",
					"source": {
						"file": "packages/http/src/cookie-handler.ts",
						"line": 121
					}
				},
				{
					"id": "sign-in",
					"kind": "jump",
					"title": "auth.signIn",
					"text": "Дальше путь входа ядра.",
					"jump": {
						"flow": "sign-in",
						"node": "start"
					}
				},
				{
					"id": "refused",
					"kind": "end-fail",
					"title": "Отказ или step-up",
					"text": "Один общий код на операцию; требование второго фактора возвращает continuation, cookie сессии не ставится."
				},
				{
					"id": "cookie",
					"kind": "end-ok",
					"title": "200 и Set-Cookie",
					"fn": "signedIn",
					"text": "HttpOnly, Secure, __Host-, Path=/, без Domain, явный SameSite (Lax по умолчанию, Strict по выбору). Токена в теле нет.",
					"source": {
						"file": "packages/http/src/cookie-handler.ts",
						"line": 137
					}
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "route",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "route",
					"to": "route-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "route",
					"to": "origin",
					"label": "да",
					"kind": "ok"
				},
				{
					"from": "origin",
					"to": "origin-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "origin",
					"to": "json",
					"label": "да",
					"kind": "ok"
				},
				{
					"from": "json",
					"to": "json-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "json",
					"to": "limit",
					"label": "да",
					"kind": "ok"
				},
				{
					"from": "limit",
					"to": "limit-bad",
					"label": "выше предела",
					"kind": "fail"
				},
				{
					"from": "limit",
					"to": "device",
					"label": "в пределах или off",
					"kind": "ok"
				},
				{
					"from": "device",
					"to": "sign-in",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "sign-in",
					"to": "refused",
					"label": "отказ",
					"kind": "fail"
				},
				{
					"from": "sign-in",
					"to": "cookie",
					"label": "вход",
					"kind": "ok"
				}
			]
		},
		{
			"id": "http-bearer",
			"group": "Вход",
			"title": "HTTP: приложение или сервер (Bearer)",
			"summary": "Обработчик для клиентов, которые носят токен сами. Токен приходит в теле, cookie не ставятся и не читаются, поэтому браузер нельзя заставить говорить от имени человека. Для страниц в браузере есть CORS по точному списку.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "POST /sign-in/<фактор>",
					"fn": "createBearerHandler",
					"input": "Request (JSON, device, Authorization)",
					"output": "Response",
					"source": {
						"file": "packages/http/src/bearer-handler.ts",
						"line": 36
					}
				},
				{
					"id": "preflight",
					"kind": "decision",
					"title": "Предпроверка браузера (OPTIONS)?",
					"fn": "preflight",
					"text": "Отвечает только источникам из allowedOrigins, точно по значению, без звёздочки и без credentials.",
					"source": {
						"file": "packages/http/src/bearer-handler.ts",
						"line": 49
					}
				},
				{
					"id": "preflight-bad",
					"kind": "end-fail",
					"title": "403 без CORS-заголовков",
					"codes": [
						"forbidden"
					]
				},
				{
					"id": "json",
					"kind": "decision",
					"title": "Тело: JSON-объект в пределе?",
					"fn": "readBody",
					"source": {
						"file": "packages/http/src/handler.ts",
						"line": 143
					}
				},
				{
					"id": "json-bad",
					"kind": "end-fail",
					"title": "400, 413 или 415",
					"codes": [
						"400",
						"413",
						"415"
					]
				},
				{
					"id": "limit",
					"kind": "decision",
					"title": "Лимит попыток",
					"fn": "applyLimit",
					"source": {
						"file": "packages/http/src/handler.ts",
						"line": 275
					}
				},
				{
					"id": "limit-bad",
					"kind": "end-fail",
					"title": "429 и Retry-After",
					"codes": [
						"rate-limited"
					]
				},
				{
					"id": "device",
					"kind": "decision",
					"title": "device: случайная строка не короче 16 знаков?",
					"fn": "deviceFor",
					"text": "Имя вроде phone отвергается: от device зависит, что завершит выход с устройства.",
					"source": {
						"file": "packages/http/src/bearer-handler.ts",
						"line": 78
					}
				},
				{
					"id": "device-bad",
					"kind": "end-fail",
					"title": "400 invalid-request",
					"codes": [
						"invalid-request"
					]
				},
				{
					"id": "sign-in",
					"kind": "jump",
					"title": "auth.signIn",
					"text": "Дальше путь входа ядра.",
					"jump": {
						"flow": "sign-in",
						"node": "start"
					}
				},
				{
					"id": "refused",
					"kind": "end-fail",
					"title": "Отказ или step-up"
				},
				{
					"id": "token",
					"kind": "end-ok",
					"title": "200 и токен в теле",
					"fn": "signedIn",
					"text": "Set-Cookie нет. Дальше клиент шлёт Authorization: Bearer <токен>; токен в адресе не читается.",
					"source": {
						"file": "packages/http/src/bearer-handler.ts",
						"line": 86
					}
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "preflight",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "preflight",
					"to": "preflight-bad",
					"label": "источника нет в списке",
					"kind": "fail"
				},
				{
					"from": "preflight",
					"to": "json",
					"label": "не OPTIONS",
					"kind": "ok"
				},
				{
					"from": "json",
					"to": "json-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "json",
					"to": "limit",
					"label": "да",
					"kind": "ok"
				},
				{
					"from": "limit",
					"to": "limit-bad",
					"label": "выше предела",
					"kind": "fail"
				},
				{
					"from": "limit",
					"to": "device",
					"label": "в пределах или off",
					"kind": "ok"
				},
				{
					"from": "device",
					"to": "device-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "device",
					"to": "sign-in",
					"label": "да",
					"kind": "ok"
				},
				{
					"from": "sign-in",
					"to": "refused",
					"label": "отказ",
					"kind": "fail"
				},
				{
					"from": "sign-in",
					"to": "token",
					"label": "вход",
					"kind": "ok"
				}
			]
		},
		{
			"id": "session-verify",
			"group": "Сессии и агенты",
			"title": "Проверка сессии",
			"summary": "Горячий путь: подпись и ровно одно обращение к хранилищу эпох, ноль запросов к базе. Токен не хранится на сервере, поэтому отзыв работает через штампы эпох.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "sessions.verify(token)",
					"fn": "auth.sessions.verify",
					"text": "Приложение проверяет токен на каждом запросе.",
					"input": "строка-токен из cookie или заголовка",
					"output": "Result<VerifiedSession>",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 376
					}
				},
				{
					"id": "unseal",
					"kind": "step",
					"title": "Расшифровать и проверить печать",
					"fn": "sealer.unseal(token, 'session')",
					"text": "Версия секрета → ключ HKDF → AES-GCM. Цель «session» входит в ключ: токен агента здесь не расшифруется. Локальный срок печати тоже проверяется (внешняя граница).",
					"jump": {
						"flow": "sealer",
						"node": "u-start"
					},
					"audit": "seal.unseal (отказ)",
					"source": {
						"file": "packages/core/src/sealer.ts",
						"line": 299
					}
				},
				{
					"id": "chain",
					"kind": "step",
					"title": "Разобрать цепочку",
					"fn": "parseChain",
					"text": "Допустима только форма тенант → пользователь → устройство → сессия, каждый уровень со своим числовым штампом. Любая другая форма, порядок или тип отвергаются (A20).",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 215
					}
				},
				{
					"id": "read",
					"kind": "port",
					"title": "Прочитать эпохи",
					"fn": "EpochStore.read",
					"port": "EpochStore.read(keys)",
					"text": "Один обмен: время хранилища и текущий штамп каждого уровня. Это единственное обращение к внешней системе на проверку.",
					"source": {
						"file": "packages/core/src/session-tokens/epoch-store.ts",
						"line": 32
					}
				},
				{
					"id": "d-expiry",
					"kind": "decision",
					"title": "Срок не истёк?",
					"text": "Сравнение по часам хранилища эпох, а не по часам сервера приложения."
				},
				{
					"id": "d-extra",
					"kind": "decision",
					"title": "Методы и время входа на месте?",
					"text": "Токен без methods и authenticatedAtMilliseconds считается повреждённым."
				},
				{
					"id": "d-revoked",
					"kind": "decision",
					"title": "Штампы токена не меньше текущих?",
					"text": "Если хоть один уровень отозван (его штамп поднялся выше записанного в токене), токен мёртв. Так отзыв тенанта, пользователя, устройства или сессии убивает все токены ниже."
				},
				{
					"id": "invalid",
					"kind": "end-fail",
					"title": "invalid-session",
					"text": "Один и тот же ответ на любую причину. Причина записана только в аудите (session.verify): invalid-seal, malformed-chain, expired, malformed, revoked.",
					"codes": [
						"invalid-session"
					],
					"audit": "session.verify (refusal) с причиной и уровнем отзыва"
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "VerifiedSession",
					"text": "Успех не пишется в аудит: это горячий путь.",
					"output": "{ tenant, subject, device, session, methods, authenticatedAtMilliseconds, authenticationAgeMilliseconds }"
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "unseal",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "unseal",
					"to": "invalid",
					"label": "печать не сошлась",
					"kind": "fail"
				},
				{
					"from": "unseal",
					"to": "chain",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "chain",
					"to": "invalid",
					"label": "форма не та",
					"kind": "fail"
				},
				{
					"from": "chain",
					"to": "read",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "read",
					"to": "d-expiry",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-expiry",
					"to": "invalid",
					"label": "истёк",
					"kind": "fail"
				},
				{
					"from": "d-expiry",
					"to": "d-extra",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-extra",
					"to": "invalid",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-extra",
					"to": "d-revoked",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-revoked",
					"to": "invalid",
					"label": "отозван",
					"kind": "fail"
				},
				{
					"from": "d-revoked",
					"to": "ok",
					"label": "да",
					"kind": "branch"
				}
			]
		},
		{
			"id": "revoke",
			"group": "Сессии и агенты",
			"title": "Отзыв",
			"summary": "Отзыв поднимает штамп уровня в хранилище эпох. Токены ничего не хранят о себе, поэтому каждый токен с этим уровнем в цепочке перестаёт проходить проверку сразу.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "sessions.revoke(level)",
					"fn": "auth.sessions.revoke",
					"text": "Приложение отзывает один уровень: выход с устройства, «забыть все сессии», блокировка пользователя, отзыв агента или разрешения.",
					"input": "{ tenant, scope: tenant | user | device | session | agent | delegation, id }",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 586
					}
				},
				{
					"id": "key",
					"kind": "step",
					"title": "Ключ уровня",
					"text": "{тенант}:уровень:id. Для уровня tenant id равен самому тенанту. Все ключи тенанта лежат в одном слоте Redis Cluster."
				},
				{
					"id": "bump",
					"kind": "port",
					"title": "Поднять штамп",
					"fn": "EpochStore.revoke",
					"port": "EpochStore.revoke(key, timeToLive)",
					"text": "Атомарно ставит штамп max(текущий + 1, now) по часам хранилища. Штамп никогда не уменьшается. Срок жизни ключа равен максимальному сроку токена, поэтому ключ переживёт любой выданный токен.",
					"throws": "Сбой хранилища пробрасывается: отзыв не должен молча не сработать.",
					"source": {
						"file": "packages/core/src/session-tokens/epoch-store.ts",
						"line": 32
					}
				},
				{
					"id": "audit",
					"kind": "step",
					"title": "Запись в аудит",
					"text": "После отзыва, чтобы сбой хука аудита не мог его заблокировать.",
					"audit": "session.revoke"
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "Готово",
					"text": "Каскад вниз по цепочке:",
					"output": "tenant → все; user → все сессии и все агенты человека; device → сессии устройства и привязанные к ним агенты; session → эта сессия и привязанные агенты; agent → делегирования этому агенту у всех людей; delegation → только это разрешение"
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "key",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "key",
					"to": "bump",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "bump",
					"to": "audit",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "audit",
					"to": "ok",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "agent-delegate",
			"group": "Сессии и агенты",
			"title": "Агенты: делегирование",
			"summary": "Человек разрешает агенту действовать от его имени. Делегируют по токену живой сессии: ядро само её проверяет, поэтому подделать делегирующего или выйти за тенант нельзя.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "agents.delegate(sessionToken, input)",
					"fn": "auth.agents.delegate",
					"input": "токен сессии, { agent, timeToLive: Duration, boundToSession? }",
					"output": "Result<{ token, delegation }>",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 515
					}
				},
				{
					"id": "verify",
					"kind": "jump",
					"title": "Проверить сессию делегирующего",
					"fn": "verifySession",
					"text": "Тот же путь, что проверка сессии. Токен агента здесь не подойдёт: агентом нельзя делегировать дальше.",
					"jump": {
						"flow": "session-verify",
						"node": "start"
					}
				},
				{
					"id": "bad-session",
					"kind": "end-fail",
					"title": "invalid-session",
					"codes": [
						"invalid-session"
					]
				},
				{
					"id": "d-input",
					"kind": "decision",
					"title": "Имя и срок годятся?",
					"text": "Имя агента: непустой текст без управляющих символов. Срок: Duration из defineDuration не больше максимума."
				},
				{
					"id": "bad-input",
					"kind": "end-fail",
					"title": "invalid-request",
					"codes": [
						"invalid-request"
					]
				},
				{
					"id": "d-bound",
					"kind": "decision",
					"title": "Привязать к сессии?",
					"text": "С привязкой агент живёт, пока жива сессия (и устройство) делегирующего. Без привязки переживает выход, как OAuth-разрешение."
				},
				{
					"id": "chain4",
					"kind": "step",
					"title": "Цепочка из 4 звеньев",
					"text": "тенант → пользователь → агент → делегирование"
				},
				{
					"id": "chain6",
					"kind": "step",
					"title": "Цепочка из 6 звеньев",
					"text": "тенант → пользователь → устройство → сессия → агент → делегирование"
				},
				{
					"id": "audit",
					"kind": "step",
					"title": "Запись в аудит",
					"text": "До запечатывания: если хук аудита бросит, токена не будет.",
					"audit": "delegation.grant { agent, delegation, bound }"
				},
				{
					"id": "read",
					"kind": "port",
					"title": "Прочитать эпохи",
					"fn": "EpochStore.read",
					"port": "EpochStore.read(keys)"
				},
				{
					"id": "seal",
					"kind": "step",
					"title": "Запечатать токен агента",
					"fn": "sealer.seal (цель «agent»)",
					"text": "Идентификатор делегирования генерирует ядро (случайный).",
					"jump": {
						"flow": "sealer",
						"node": "s-start"
					}
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "Delegation",
					"output": "{ token, delegation }",
					"text": "Права агента лежат вне токена: приложение по id делегирования достаёт свои запреты и строит возможности через narrow."
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "verify",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "verify",
					"to": "bad-session",
					"label": "не сессия",
					"kind": "fail"
				},
				{
					"from": "verify",
					"to": "d-input",
					"label": "жива",
					"kind": "branch"
				},
				{
					"from": "d-input",
					"to": "bad-input",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-input",
					"to": "d-bound",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-bound",
					"to": "chain4",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "d-bound",
					"to": "chain6",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "chain4",
					"to": "audit",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "chain6",
					"to": "audit",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "audit",
					"to": "read",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "read",
					"to": "seal",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "seal",
					"to": "ok",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "agent-verify",
			"group": "Сессии и агенты",
			"title": "Агенты: проверка токена",
			"summary": "Отдельная проверка, а не поле в sessions.verify: приложение, которое про агентов не знает, их не примет, а токен агента не сойдёт за человека.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "agents.verify(token)",
					"fn": "auth.agents.verify",
					"output": "Result<VerifiedAgent>",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 477
					}
				},
				{
					"id": "unseal",
					"kind": "step",
					"title": "Расшифровать (цель «agent»)",
					"fn": "sealer.unseal(token, 'agent')",
					"text": "Токен сессии здесь не расшифруется: другая цель входит в ключ.",
					"jump": {
						"flow": "sealer",
						"node": "u-start"
					}
				},
				{
					"id": "chain",
					"kind": "step",
					"title": "Разобрать цепочку",
					"fn": "parseChain",
					"text": "Допустимы две формы: 4 звена (тенант, пользователь, агент, делегирование) или 6 (с устройством и сессией)."
				},
				{
					"id": "read",
					"kind": "port",
					"title": "Прочитать эпохи",
					"fn": "EpochStore.read",
					"port": "EpochStore.read(keys)"
				},
				{
					"id": "d-live",
					"kind": "decision",
					"title": "Не истёк и не отозван?",
					"text": "Как у сессии: срок по часам хранилища, штампы всех звеньев. Агент умирает, если отозваны: тенант, человек, (устройство, сессия), агент или это делегирование."
				},
				{
					"id": "invalid",
					"kind": "end-fail",
					"title": "invalid-session",
					"text": "Тот же единый отказ; причина только в аудите (session.verify с агентом и делегированием).",
					"codes": [
						"invalid-session"
					],
					"audit": "session.verify (refusal)"
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "VerifiedAgent",
					"output": "{ tenant, subject (человек), agent, delegation, boundTo | undefined, delegatedAtMilliseconds }"
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "unseal",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "unseal",
					"to": "invalid",
					"label": "не сошлось",
					"kind": "fail"
				},
				{
					"from": "unseal",
					"to": "chain",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "chain",
					"to": "invalid",
					"label": "форма не та",
					"kind": "fail"
				},
				{
					"from": "chain",
					"to": "read",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "read",
					"to": "d-live",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-live",
					"to": "invalid",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-live",
					"to": "ok",
					"label": "да",
					"kind": "branch"
				}
			]
		},
		{
			"id": "identity",
			"group": "Данные",
			"title": "Изменение идентичности",
			"summary": "Удаление субъекта и подтверждение почты. Оба пути отзывают сессии затронутых субъектов, поэтому вытесненный или удалённый человек теряет доступ сразу.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "mutateIdentity(tenant, subject, change)",
					"fn": "auth.mutateIdentity",
					"input": "tenant, subject, { type: delete } | { type: confirm-email, proof }",
					"output": "Result<{ affectedSubjects }>",
					"source": {
						"file": "packages/core/src/identity/mutate-identity.ts",
						"line": 77
					}
				},
				{
					"id": "d-text",
					"kind": "decision",
					"title": "tenant и subject можно хранить?",
					"fn": "isStorableText",
					"text": "Пустые строки, управляющие символы и одиночные суррогаты отвергаются до хранилищ."
				},
				{
					"id": "bad-request",
					"kind": "end-fail",
					"title": "invalid-request",
					"codes": [
						"invalid-request"
					],
					"audit": "identity.mutate (malformed), tenant и subject пустые"
				},
				{
					"id": "d-type",
					"kind": "decision",
					"title": "Какое изменение?"
				},
				{
					"id": "revoke-user",
					"kind": "port",
					"title": "Отозвать человека",
					"fn": "revokeUser → EpochStore.revoke",
					"port": "EpochStore.revoke(userKey)",
					"text": "Сначала отзыв, потом удаление: между ними нет окна с живой сессией удаляемого.",
					"source": {
						"file": "packages/core/src/session-tokens/epoch-store.ts",
						"line": 32
					}
				},
				{
					"id": "delete",
					"kind": "port",
					"title": "Удалить субъекта",
					"fn": "IdentityStore.deleteSubject",
					"port": "IdentityStore.deleteSubject(tenant, subjectId)",
					"text": "Удаляет все идентичности субъекта этого тенанта. Чужой тенант не затрагивается. Возвращает false, если такого нет.",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "d-deleted",
					"kind": "decision",
					"title": "Субъект был?"
				},
				{
					"id": "no-subject",
					"kind": "end-fail",
					"title": "no-subject",
					"codes": [
						"no-subject"
					],
					"audit": "identity.mutate, reason: not-found"
				},
				{
					"id": "deleted",
					"kind": "end-ok",
					"title": "affectedSubjects: [subject]",
					"audit": "identity.mutate, reason: deleted"
				},
				{
					"id": "d-proof",
					"kind": "decision",
					"title": "Доказательство выдано ядром?",
					"text": "Проверка по реестру чеканки: подделанный объект не пройдёт."
				},
				{
					"id": "no-proof",
					"kind": "end-fail",
					"title": "no-proof",
					"codes": [
						"no-proof"
					],
					"audit": "identity.mutate, reason: no-proof"
				},
				{
					"id": "d-verified",
					"kind": "decision",
					"title": "Почта подтверждена?"
				},
				{
					"id": "forbidden",
					"kind": "end-fail",
					"title": "forbidden",
					"codes": [
						"forbidden"
					],
					"audit": "identity.mutate, reason: unverified | not-owner"
				},
				{
					"id": "owner",
					"kind": "port",
					"title": "Владелец подтверждённой почты",
					"fn": "IdentityStore.findSubjectByVerifiedEmail",
					"port": "IdentityStore.findSubjectByVerifiedEmail(tenant, email)",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "d-owner",
					"kind": "decision",
					"title": "Владелец это subject?",
					"text": "Подтвердить почту за другого нельзя."
				},
				{
					"id": "claimants",
					"kind": "port",
					"title": "Кто претендовал без подтверждения",
					"fn": "IdentityStore.findSubjectsByUnverifiedEmail",
					"port": "IdentityStore.findSubjectsByUnverifiedEmail(tenant, email)",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "revoke-early",
					"kind": "port",
					"title": "Отозвать претендентов",
					"fn": "revokeUser",
					"port": "EpochStore.revoke(userKey) для каждого",
					"text": "До снятия претензий: захватчик теряет сессии прежде, чем исчезнут его данные."
				},
				{
					"id": "remove",
					"kind": "port",
					"title": "Снять претензии",
					"fn": "IdentityStore.removeUnverifiedEmailClaims",
					"port": "IdentityStore.removeUnverifiedEmailClaims(tenant, email, keep)",
					"text": "Одной операцией: снимает неподтверждённые претензии на адрес у всех, кроме владельца и subject, удаляет субъектов, оставшихся без идентичностей, возвращает затронутых.",
					"source": {
						"file": "packages/core/src/identity/identity-store.ts",
						"line": 12
					}
				},
				{
					"id": "revoke-late",
					"kind": "port",
					"title": "Отозвать опоздавших",
					"fn": "revokeUser",
					"port": "EpochStore.revoke(userKey) для тех, кто появился между чтением и снятием",
					"text": "Закрывает гонку: претендент мог появиться после первого чтения."
				},
				{
					"id": "confirmed",
					"kind": "end-ok",
					"title": "affectedSubjects: вытесненные",
					"audit": "identity.mutate, reason: email-confirmed"
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "d-text",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-text",
					"to": "bad-request",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-text",
					"to": "d-type",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-type",
					"to": "revoke-user",
					"label": "delete",
					"kind": "branch"
				},
				{
					"from": "revoke-user",
					"to": "delete",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "delete",
					"to": "d-deleted",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-deleted",
					"to": "no-subject",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-deleted",
					"to": "deleted",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-type",
					"to": "d-proof",
					"label": "confirm-email",
					"kind": "branch"
				},
				{
					"from": "d-proof",
					"to": "no-proof",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-proof",
					"to": "d-verified",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-verified",
					"to": "forbidden",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-verified",
					"to": "owner",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "owner",
					"to": "d-owner",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-owner",
					"to": "forbidden",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-owner",
					"to": "claimants",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "claimants",
					"to": "revoke-early",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "revoke-early",
					"to": "remove",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "remove",
					"to": "revoke-late",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "revoke-late",
					"to": "confirmed",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "tokens",
			"group": "Данные",
			"title": "Одноразовые токены",
			"summary": "Секрет для ссылки из письма, продолжения step-up и т. п. Хранится только хэш; погасить можно один раз, только для той цели, для которой выдан, и до истечения.",
			"nodes": [
				{
					"id": "i-start",
					"kind": "start",
					"title": "tokens.issue(input)",
					"fn": "auth.tokens.issue",
					"input": "{ purpose, payload?, timeToLive: Duration }",
					"output": "секрет (строка)",
					"source": {
						"file": "packages/core/src/tokens/tokens.ts",
						"line": 83
					}
				},
				{
					"id": "i-duration",
					"kind": "decision",
					"title": "timeToLive выдан defineDuration?",
					"text": "Число сюда не пройдёт по типам; обход типов в JS даёт TypeError (значение не прошло проверку компилятора).",
					"throws": "TypeError"
				},
				{
					"id": "i-throw",
					"kind": "end-fail",
					"title": "TypeError",
					"codes": [
						"TypeError"
					]
				},
				{
					"id": "i-secret",
					"kind": "step",
					"title": "Случайный секрет и его хэш",
					"fn": "generateSecret, hashSecret",
					"text": "В хранилище уходит только SHA-256 секрета."
				},
				{
					"id": "i-put",
					"kind": "port",
					"title": "Положить запись",
					"fn": "TokenStore.put",
					"port": "TokenStore.put(hash, { purpose, payload, expiresAt })",
					"text": "Хранилище без места отвечает ошибкой переполнения (политика: отказать новому, не вытеснять живые).",
					"source": {
						"file": "packages/core/src/tokens/token-store.ts",
						"line": 24
					}
				},
				{
					"id": "i-full",
					"kind": "end-fail",
					"title": "переполнение хранилища",
					"text": "Исключение пробрасывается, в аудит пишется отказ с причиной capacity.",
					"audit": "token.issue, refusal, capacity",
					"throws": "StoreFullError"
				},
				{
					"id": "i-audit",
					"kind": "step",
					"title": "Запись в аудит",
					"audit": "token.issue (success)"
				},
				{
					"id": "i-ok",
					"kind": "end-ok",
					"title": "Секрет выдан",
					"text": "Секрет показывают человеку один раз (например, в ссылке)."
				},
				{
					"id": "c-start",
					"kind": "start",
					"title": "tokens.consume(token, purpose)",
					"fn": "auth.tokens.consume",
					"input": "секрет, ожидаемая цель",
					"output": "Result<payload>",
					"source": {
						"file": "packages/core/src/tokens/tokens.ts",
						"line": 118
					}
				},
				{
					"id": "c-length",
					"kind": "decision",
					"title": "Длина секрета верна?",
					"text": "Дешёвая отсечка мусора до обращения к хранилищу."
				},
				{
					"id": "c-take",
					"kind": "port",
					"title": "Забрать запись",
					"fn": "TokenStore.take",
					"port": "TokenStore.take(hash)",
					"text": "Атомарно удаляет и возвращает запись: из любого числа параллельных take запись достаётся одному. Postgres: delete returning; Redis: Lua; память: одна синхронная операция.",
					"source": {
						"file": "packages/core/src/tokens/token-store.ts",
						"line": 24
					}
				},
				{
					"id": "c-found",
					"kind": "decision",
					"title": "Запись была?"
				},
				{
					"id": "c-purpose",
					"kind": "decision",
					"title": "Цель совпала?",
					"text": "Токен, предъявленный не для своей цели, сожжён (take уже удалил запись)."
				},
				{
					"id": "c-expiry",
					"kind": "decision",
					"title": "Не истёк?",
					"text": "Срок проверяет вызывающий (ядро), а не хранилище: TTL хранилища только сборка мусора."
				},
				{
					"id": "c-refuse",
					"kind": "end-fail",
					"title": "invalid-token",
					"text": "Одинаковый ответ на любую причину. Причины в аудите: malformed, not-found, wrong-purpose, expired.",
					"codes": [
						"invalid-token"
					],
					"audit": "token.consume (refusal)"
				},
				{
					"id": "c-audit",
					"kind": "step",
					"title": "Запись в аудит",
					"text": "До выдачи payload: если хук бросит, погашение провалится, а токен уже потрачен.",
					"audit": "token.consume (success, consumed)"
				},
				{
					"id": "c-ok",
					"kind": "end-ok",
					"title": "payload",
					"output": "Record<string, string>"
				}
			],
			"edges": [
				{
					"from": "i-start",
					"to": "i-duration",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "i-duration",
					"to": "i-throw",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "i-duration",
					"to": "i-secret",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "i-secret",
					"to": "i-put",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "i-put",
					"to": "i-full",
					"label": "нет места",
					"kind": "fail"
				},
				{
					"from": "i-put",
					"to": "i-audit",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "i-audit",
					"to": "i-ok",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "c-start",
					"to": "c-length",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "c-length",
					"to": "c-refuse",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "c-length",
					"to": "c-take",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "c-take",
					"to": "c-found",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "c-found",
					"to": "c-refuse",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "c-found",
					"to": "c-purpose",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "c-purpose",
					"to": "c-refuse",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "c-purpose",
					"to": "c-expiry",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "c-expiry",
					"to": "c-refuse",
					"label": "истёк",
					"kind": "fail"
				},
				{
					"from": "c-expiry",
					"to": "c-audit",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "c-audit",
					"to": "c-ok",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "email-link",
			"group": "Данные",
			"title": "Фактор: ссылка из письма",
			"summary": "Пример фактора-плагина. Два вызова: выдать ссылку (challenge) и проверить её при входе (verify). Доставка письма не в запросе: приложение передаёт её в outbox.",
			"nodes": [
				{
					"id": "ch-start",
					"kind": "start",
					"title": "emailLink.challenge(email)",
					"fn": "emailLink.challenge",
					"text": "Приложение обычно ставит перед ним счётчик (meter) по адресу.",
					"source": {
						"file": "packages/factor-email-link/src/email-link.ts",
						"line": 99
					}
				},
				{
					"id": "ch-canon",
					"kind": "decision",
					"title": "Адрес приемлем?",
					"fn": "canonicalizeEmail",
					"text": "NFKC, регистр локальной части, домен через разбор URL (UTS #46). Кавычки, комментарии, слишком длинные части, управляющие символы и пробелы отвергаются.",
					"source": {
						"file": "packages/core/src/identity/canonical-email.ts",
						"line": 85
					}
				},
				{
					"id": "ch-bad",
					"kind": "end-fail",
					"title": "invalid-email",
					"codes": [
						"invalid-email"
					]
				},
				{
					"id": "ch-issue",
					"kind": "jump",
					"title": "Выдать токен",
					"fn": "tokens.issue(email-link)",
					"text": "payload { email: канонический адрес }.",
					"jump": {
						"flow": "tokens",
						"node": "i-start"
					}
				},
				{
					"id": "ch-deliver",
					"kind": "step",
					"title": "Отдать письмо приложению",
					"fn": "options.deliver({ email, token })",
					"text": "Колбэк приложения. Держите его коротким: ставьте письмо в outbox, а не зовите почтовый сервис внутри запроса. Исключение дойдёт до вызывающего.",
					"jump": {
						"flow": "outbox",
						"node": "e-start"
					}
				},
				{
					"id": "ch-ok",
					"kind": "end-ok",
					"title": "Ссылка отправлена"
				},
				{
					"id": "v-start",
					"kind": "start",
					"title": "factor.verify(response)",
					"fn": "emailLink.factor.verify",
					"text": "Вызывается из verifyProof при входе. response это токен из ссылки.",
					"source": {
						"file": "packages/factor-email-link/src/email-link.ts",
						"line": 69
					}
				},
				{
					"id": "v-string",
					"kind": "decision",
					"title": "response это строка?"
				},
				{
					"id": "v-bad",
					"kind": "end-fail",
					"title": "invalid-token",
					"codes": [
						"invalid-token"
					]
				},
				{
					"id": "v-consume",
					"kind": "jump",
					"title": "Погасить токен",
					"fn": "tokens.consume(email-link)",
					"jump": {
						"flow": "tokens",
						"node": "c-start"
					}
				},
				{
					"id": "v-email",
					"kind": "decision",
					"title": "В payload есть email?"
				},
				{
					"id": "v-claims",
					"kind": "end-ok",
					"title": "Claims почты",
					"output": "{ provider: email, externalId: email, email, emailVerified: true }",
					"text": "Идут в verifyProof, который проверит их по закрытой форме и создаст Proof."
				}
			],
			"edges": [
				{
					"from": "ch-start",
					"to": "ch-canon",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "ch-canon",
					"to": "ch-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "ch-canon",
					"to": "ch-issue",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "ch-issue",
					"to": "ch-deliver",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "ch-deliver",
					"to": "ch-ok",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "v-start",
					"to": "v-string",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "v-string",
					"to": "v-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "v-string",
					"to": "v-consume",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "v-consume",
					"to": "v-bad",
					"label": "отказ",
					"kind": "fail"
				},
				{
					"from": "v-consume",
					"to": "v-email",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "v-email",
					"to": "v-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "v-email",
					"to": "v-claims",
					"label": "да",
					"kind": "branch"
				}
			]
		},
		{
			"id": "sealer",
			"group": "Данные",
			"title": "Запечатывание",
			"summary": "Зашифрованные, подписанные, привязанные к цели значения без состояния на сервере: токены сессий и агентов, OAuth state. В отличие от токенов, печать не одноразовая.",
			"nodes": [
				{
					"id": "s-start",
					"kind": "start",
					"title": "sealer.seal(input)",
					"fn": "auth.sealer.seal",
					"input": "{ purpose, payload?, timeToLive: Duration }",
					"output": "«версия.base64url»",
					"source": {
						"file": "packages/core/src/sealer.ts",
						"line": 272
					}
				},
				{
					"id": "s-duration",
					"kind": "decision",
					"title": "timeToLive выдан defineDuration?",
					"throws": "TypeError"
				},
				{
					"id": "s-throw",
					"kind": "end-fail",
					"title": "TypeError",
					"codes": [
						"TypeError"
					]
				},
				{
					"id": "s-key",
					"kind": "step",
					"title": "Ключ сообщения",
					"text": "HKDF от текущего секрета (первого в списке), случайной соли и цели. Другая цель или соль дают другой ключ."
				},
				{
					"id": "s-encrypt",
					"kind": "step",
					"title": "Шифрование AES-GCM",
					"text": "Случайный вектор инициализации; внутри { payload, expiresAt }. Соль, вектор и шифртекст в base64url, спереди номер версии секрета."
				},
				{
					"id": "s-ok",
					"kind": "end-ok",
					"title": "Запечатанное значение"
				},
				{
					"id": "u-start",
					"kind": "start",
					"title": "sealer.unseal(sealed, purpose)",
					"fn": "auth.sealer.unseal",
					"input": "значение, ожидаемая цель",
					"output": "Result<payload>",
					"source": {
						"file": "packages/core/src/sealer.ts",
						"line": 299
					}
				},
				{
					"id": "u-parse",
					"kind": "decision",
					"title": "Формат «версия.тело» верен?",
					"text": "Версия: цифры без ведущих нулей, ограниченная длина."
				},
				{
					"id": "u-version",
					"kind": "decision",
					"title": "Версия секрета известна?",
					"text": "Секрет можно ротировать: новый ставят первым, старый оставляют, пока не истекут запечатанные им значения."
				},
				{
					"id": "u-decrypt",
					"kind": "decision",
					"title": "Расшифровалось?",
					"text": "Неверная цель, чужой секрет или правка значения дают одну и ту же ошибку."
				},
				{
					"id": "u-expiry",
					"kind": "decision",
					"title": "Не истекло?"
				},
				{
					"id": "u-refuse",
					"kind": "end-fail",
					"title": "invalid-seal",
					"codes": [
						"invalid-seal"
					],
					"audit": "seal.unseal (refusal): malformed | unknown-version | undecryptable | expired"
				},
				{
					"id": "u-ok",
					"kind": "end-ok",
					"title": "payload"
				}
			],
			"edges": [
				{
					"from": "s-start",
					"to": "s-duration",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-duration",
					"to": "s-throw",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "s-duration",
					"to": "s-key",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "s-key",
					"to": "s-encrypt",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "s-encrypt",
					"to": "s-ok",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "u-start",
					"to": "u-parse",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "u-parse",
					"to": "u-refuse",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "u-parse",
					"to": "u-version",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "u-version",
					"to": "u-refuse",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "u-version",
					"to": "u-decrypt",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "u-decrypt",
					"to": "u-refuse",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "u-decrypt",
					"to": "u-expiry",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "u-expiry",
					"to": "u-refuse",
					"label": "истекло",
					"kind": "fail"
				},
				{
					"from": "u-expiry",
					"to": "u-ok",
					"label": "да",
					"kind": "branch"
				}
			]
		},
		{
			"id": "meter",
			"group": "Защита",
			"title": "Счётчик запросов",
			"summary": "Скользящее окно как у Cloudflare: два счётчика на ключ, оценка = прошлый × (окно − прошло) / окно + текущий. Отказанный запрос ничего не считает и получает точный момент, когда пройдёт.",
			"nodes": [
				{
					"id": "define",
					"kind": "start",
					"title": "defineMeterRule({ limit, windowMilliseconds })",
					"fn": "defineMeterRule",
					"text": "Правило определяется один раз при старте. Не бросает: плохие числа (не положительные целые) дают invalid-request. Запросный API принимает только такое правило.",
					"output": "Result<MeterRule>",
					"codes": [
						"invalid-request"
					],
					"source": {
						"file": "packages/core/src/meter/meter.ts",
						"line": 50
					}
				},
				{
					"id": "start",
					"kind": "start",
					"title": "meter.consume(scope, rule, cost = 1)",
					"fn": "auth.meter.consume",
					"text": "observe(scope, rule, cost) идёт тем же путём, но никогда не отказывает: запрос, который consume отказал бы, пропускается и пишется в аудит как наблюдение (выкатка нового лимита).",
					"input": "{ tenant, actor, resource }, MeterRule, cost",
					"output": "Result<{ used, remaining, resetsAtMilliseconds }, MeterRefusal>",
					"source": {
						"file": "packages/core/src/meter/meter.ts",
						"line": 178
					}
				},
				{
					"id": "d-valid",
					"kind": "decision",
					"title": "Правило выдано defineMeterRule, цена целая и не больше лимита?",
					"fn": "decide",
					"text": "Цена это данные запроса, поэтому её проверка отказ, а не исключение. Ничего не считается.",
					"source": {
						"file": "packages/core/src/meter/meter.ts",
						"line": 131
					}
				},
				{
					"id": "bad",
					"kind": "end-fail",
					"title": "invalid-request",
					"codes": [
						"invalid-request"
					]
				},
				{
					"id": "store",
					"kind": "port",
					"title": "Посчитать",
					"fn": "MeterStore.consume",
					"port": "MeterStore.consume({ key, cost, limit, windowMilliseconds })",
					"text": "Один атомарный шаг по часам самого хранилища, решает как slidingWindow. Нет места под ключ: отказ (refusedForCapacity), а не пропуск. Redis: Lua; память: синхронно.",
					"source": {
						"file": "packages/core/src/meter/meter-store.ts",
						"line": 21
					}
				},
				{
					"id": "d-allowed",
					"kind": "decision",
					"title": "Укладывается в лимит?"
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "Reading",
					"text": "Успехи в аудит не пишутся: это горячий путь.",
					"output": "{ used, remaining, resetsAtMilliseconds }"
				},
				{
					"id": "audit",
					"kind": "step",
					"title": "Запись отказа в аудит",
					"audit": "meter.consume (refusal), причина limit-exceeded | capacity"
				},
				{
					"id": "limited",
					"kind": "end-fail",
					"title": "rate-limited",
					"output": "{ code: rate-limited, resetsAtMilliseconds }",
					"text": "Приложение отвечает 429 и Retry-After по resetsAtMilliseconds.",
					"codes": [
						"rate-limited"
					]
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "d-valid",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-valid",
					"to": "bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-valid",
					"to": "store",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "store",
					"to": "d-allowed",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-allowed",
					"to": "ok",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-allowed",
					"to": "audit",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "audit",
					"to": "limited",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "authorize",
			"group": "Защита",
			"title": "Права после входа",
			"summary": "Решение «можно ли этому субъекту это действие над этим ресурсом». Правила это сериализуемые данные (vetojs). По умолчанию запрет; делегат получает подмножество прав делегирующего.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "authorize(ability, request, context)",
					"fn": "authorize",
					"input": "Ability, { action, resource, row? }, { tenant, subject, audit }",
					"output": "Result<undefined>",
					"source": {
						"file": "packages/authorize/src/authorize.ts",
						"line": 46
					}
				},
				{
					"id": "check",
					"kind": "step",
					"title": "Спросить возможности",
					"fn": "ability.authorize (vetojs)",
					"text": "Выбрасывает ForbiddenError на запрете. Любое другое исключение (например, не загруженная связь) это ошибка проверки."
				},
				{
					"id": "d-result",
					"kind": "decision",
					"title": "Что случилось?"
				},
				{
					"id": "audit",
					"kind": "step",
					"title": "Запись вердикта",
					"text": "Каждый вердикт пишется до возврата: если хук бросит, нет и allow.",
					"audit": "authorize.check, reason: allowed | forbidden | authorize-error"
				},
				{
					"id": "d-allowed",
					"kind": "decision",
					"title": "Разрешено?"
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "ok"
				},
				{
					"id": "forbidden",
					"kind": "end-fail",
					"title": "forbidden",
					"codes": [
						"forbidden"
					],
					"text": "Запрет и ошибка проверки дают один ответ. Закрыто."
				},
				{
					"id": "n-start",
					"kind": "start",
					"title": "narrow(ac, delegator, denies)",
					"fn": "narrow",
					"text": "Права агента из прав делегирующего плюс дополнительные запреты. Расширить права нельзя: любое правило, кроме deny, отклоняет делегирование.",
					"input": "карта ресурсов, Ability делегирующего, CheckedRule[]",
					"output": "Result<Ability>",
					"source": {
						"file": "packages/authorize/src/narrow.ts",
						"line": 18
					}
				},
				{
					"id": "n-denies",
					"kind": "decision",
					"title": "Все правила это deny?"
				},
				{
					"id": "n-bad",
					"kind": "end-fail",
					"title": "invalid-delegation",
					"codes": [
						"invalid-delegation"
					]
				},
				{
					"id": "n-ok",
					"kind": "end-ok",
					"title": "Ability делегата",
					"text": "Права делегата всегда подмножество прав делегирующего, а его ограничения сохраняются (property-тест)."
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "check",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "check",
					"to": "d-result",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-result",
					"to": "audit",
					"label": "разрешено / ForbiddenError / иная ошибка",
					"kind": "branch"
				},
				{
					"from": "audit",
					"to": "d-allowed",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-allowed",
					"to": "ok",
					"label": "allowed",
					"kind": "branch"
				},
				{
					"from": "d-allowed",
					"to": "forbidden",
					"label": "иначе",
					"kind": "fail"
				},
				{
					"from": "n-start",
					"to": "n-denies",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "n-denies",
					"to": "n-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "n-denies",
					"to": "n-ok",
					"label": "да",
					"kind": "branch"
				}
			]
		},
		{
			"id": "transport",
			"group": "Защита",
			"title": "Редиректы и исходящие вызовы",
			"summary": "Две проверки на границе: куда можно отправить браузер после входа (открытые редиректоры, RFC 9700) и куда может ходить приложение само (SSRF, OWASP).",
			"nodes": [
				{
					"id": "r-start",
					"kind": "start",
					"title": "redirect(target)",
					"fn": "createRedirectPolicy(options)(target)",
					"text": "Список разрешённых origin проверяется при создании (бросок RangeError при старте): точные origin, без шаблонов, http только для loopback.",
					"output": "Result<строка для Location>",
					"source": {
						"file": "packages/core/src/transport/redirect-policy.ts",
						"line": 48
					}
				},
				{
					"id": "r-text",
					"kind": "decision",
					"title": "Строка допустима?",
					"text": "Текст до 2048 знаков без обратной косой, управляющих символов и пробелов любого письма: браузер читает такие строки иначе, чем проверяющий."
				},
				{
					"id": "r-bad",
					"kind": "end-fail",
					"title": "invalid-request",
					"codes": [
						"invalid-request"
					]
				},
				{
					"id": "r-path",
					"kind": "decision",
					"title": "Начинается с «/»?"
				},
				{
					"id": "r-double",
					"kind": "decision",
					"title": "Начинается с «//»?",
					"text": "«//evil.com» это адрес другого сайта."
				},
				{
					"id": "r-path-ok",
					"kind": "end-ok",
					"title": "Путь этого сайта"
				},
				{
					"id": "r-origin",
					"kind": "decision",
					"title": "Абсолютный URL с origin из списка, без логина и пароля?",
					"text": "Точное совпадение origin (схема, хост, порт)."
				},
				{
					"id": "r-url-ok",
					"kind": "end-ok",
					"title": "Нормализованный URL"
				},
				{
					"id": "o-start",
					"kind": "start",
					"title": "guard.fetch(target, init)",
					"fn": "createOutboundGuard(options)",
					"text": "check(target) делает проверки, fetch(target) вызывает их и затем запрос с redirect: error и cache: no-store.",
					"output": "Result<Response>",
					"source": {
						"file": "packages/core/src/transport/outbound-guard.ts",
						"line": 59
					}
				},
				{
					"id": "o-shape",
					"kind": "decision",
					"title": "https, порт по умолчанию, без логина, хост в списке?",
					"text": "Сначала список разрешённых имён, и только они. IP-адрес в качестве хоста запрещён."
				},
				{
					"id": "o-forbidden",
					"kind": "end-fail",
					"title": "forbidden",
					"codes": [
						"forbidden"
					]
				},
				{
					"id": "o-resolve",
					"kind": "decision",
					"title": "Все адреса имени публичные?",
					"fn": "resolveAddresses + isPublicAddress",
					"text": "Если передан резолвер: каждый адрес должен быть глобально маршрутизируемым (частные, loopback, link-local, документация, multicast, а также IPv4 внутри IPv6). Пустой ответ и сбой резолвера это запрет. Окно DNS rebinding закрывает только сетевое ограничение исходящего трафика.",
					"source": {
						"file": "packages/core/src/transport/public-address.ts",
						"line": 179
					}
				},
				{
					"id": "o-call",
					"kind": "step",
					"title": "Вызов без редиректов",
					"text": "fetch с redirect: error: ответ-редирект не будет принят."
				},
				{
					"id": "o-unavailable",
					"kind": "end-fail",
					"title": "unavailable",
					"codes": [
						"unavailable"
					],
					"text": "Сбой сети."
				},
				{
					"id": "o-ok",
					"kind": "end-ok",
					"title": "Response"
				}
			],
			"edges": [
				{
					"from": "r-start",
					"to": "r-text",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "r-text",
					"to": "r-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "r-text",
					"to": "r-path",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "r-path",
					"to": "r-double",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "r-double",
					"to": "r-bad",
					"label": "да",
					"kind": "fail"
				},
				{
					"from": "r-double",
					"to": "r-path-ok",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "r-path",
					"to": "r-origin",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "r-origin",
					"to": "r-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "r-origin",
					"to": "r-url-ok",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "o-start",
					"to": "o-shape",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "o-shape",
					"to": "o-forbidden",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "o-shape",
					"to": "o-resolve",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "o-resolve",
					"to": "o-forbidden",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "o-resolve",
					"to": "o-call",
					"label": "да / резолвера нет",
					"kind": "branch"
				},
				{
					"from": "o-call",
					"to": "o-unavailable",
					"label": "сбой",
					"kind": "fail"
				},
				{
					"from": "o-call",
					"to": "o-ok",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "outbox",
			"group": "Асинхронность",
			"title": "Outbox: события наружу",
			"summary": "Единственный выход из запроса во внешний мир. Событие записывается в хранилище вместе с изменением, а доставляет его воркер после запроса. Сбой получателя не ломает вход. Доставка минимум один раз.",
			"nodes": [
				{
					"id": "e-start",
					"kind": "start",
					"title": "emit(event)",
					"fn": "emit",
					"input": "{ type, payload: Record<string, string> }",
					"output": "Result<id>",
					"source": {
						"file": "packages/core/src/outbox/emit.ts",
						"line": 58
					}
				},
				{
					"id": "e-shape",
					"kind": "decision",
					"title": "Событие целое?",
					"fn": "parseEvent",
					"text": "Закрытая форма: только type и payload; type это текст, который можно хранить; значения payload строки (любой текст, включая переводы строк). Ключ вроде __proto__ остаётся обычным ключом.",
					"source": {
						"file": "packages/core/src/outbox/emit.ts",
						"line": 15
					}
				},
				{
					"id": "e-bad",
					"kind": "end-fail",
					"title": "invalid-event",
					"codes": [
						"invalid-event"
					]
				},
				{
					"id": "e-append",
					"kind": "port",
					"title": "Записать событие",
					"fn": "OutboxStore.append",
					"port": "OutboxStore.append({ id, type, payload })",
					"text": "Должно попасть в ту же транзакцию, что и изменение, которое породило событие (Postgres: исполнитель транзакции). Повтор того же id ничего не меняет.",
					"source": {
						"file": "packages/core/src/outbox/outbox-store.ts",
						"line": 34
					}
				},
				{
					"id": "e-ok",
					"kind": "end-ok",
					"title": "id события"
				},
				{
					"id": "w-start",
					"kind": "start",
					"title": "worker.runOnce()",
					"fn": "createOutboxWorker",
					"text": "Вызывайте из планировщика или потребителя очереди. Параметры проверяются при создании.",
					"output": "{ completed, retried, buried }",
					"source": {
						"file": "packages/core/src/outbox/outbox-worker.ts",
						"line": 55
					}
				},
				{
					"id": "w-claim",
					"kind": "port",
					"title": "Забрать пачку",
					"fn": "OutboxStore.claim",
					"port": "OutboxStore.claim({ limit, leaseMilliseconds })",
					"text": "Прячет события от других воркеров на аренду и увеличивает attempts. Событие с истёкшей арендой снова доступно: упавший воркер ничего не теряет. Postgres: for update skip locked.",
					"source": {
						"file": "packages/core/src/outbox/outbox-store.ts",
						"line": 34
					}
				},
				{
					"id": "w-handler",
					"kind": "decision",
					"title": "Есть обработчик этого типа?",
					"text": "События без обработчика закапываются сразу, чтобы опечатка не крутилась вечно."
				},
				{
					"id": "w-run",
					"kind": "step",
					"title": "Обработчик",
					"fn": "handler(event)",
					"text": "Код приложения: письмо, вебхук. Может бросить, тогда пробуем позже. События пачки идут независимо."
				},
				{
					"id": "w-failed",
					"kind": "decision",
					"title": "Бросил?"
				},
				{
					"id": "w-attempts",
					"kind": "decision",
					"title": "Попыток уже не меньше предела?"
				},
				{
					"id": "w-complete",
					"kind": "port",
					"title": "Готово",
					"fn": "OutboxStore.complete",
					"port": "OutboxStore.complete(record)",
					"text": "Сверяет attempts: воркер с просроченной арендой не может отменить чужую выдачу."
				},
				{
					"id": "w-release",
					"kind": "port",
					"title": "Вернуть на повтор",
					"fn": "OutboxStore.release",
					"port": "OutboxStore.release(record, retryDelay)"
				},
				{
					"id": "w-bury",
					"kind": "port",
					"title": "Закопать",
					"fn": "OutboxStore.bury",
					"port": "OutboxStore.bury(record)",
					"text": "Postgres переносит запись в vow_auth_outbox_buried для разбора."
				},
				{
					"id": "w-summary",
					"kind": "end-ok",
					"title": "Итог прогона",
					"output": "{ completed, retried, buried }"
				}
			],
			"edges": [
				{
					"from": "e-start",
					"to": "e-shape",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "e-shape",
					"to": "e-bad",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "e-shape",
					"to": "e-append",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "e-append",
					"to": "e-ok",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "w-start",
					"to": "w-claim",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "w-claim",
					"to": "w-handler",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "w-handler",
					"to": "w-bury",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "w-handler",
					"to": "w-run",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "w-run",
					"to": "w-failed",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "w-failed",
					"to": "w-complete",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "w-failed",
					"to": "w-attempts",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "w-attempts",
					"to": "w-bury",
					"label": "да",
					"kind": "fail"
				},
				{
					"from": "w-attempts",
					"to": "w-release",
					"label": "нет",
					"kind": "branch"
				},
				{
					"from": "w-complete",
					"to": "w-summary",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "w-release",
					"to": "w-summary",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "w-bury",
					"to": "w-summary",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "service-server",
			"group": "Режим сервиса",
			"title": "Сервис: обработчик",
			"summary": "Fetch-обработчик (Request → Response). Порядок проверок важен: сначала секрет, потом всё остальное. Каждый ответ с Cache-Control: no-store, потому что может нести токен.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "handler(request)",
					"fn": "createAuthHandler(options)",
					"text": "Секреты сервиса (минимум один, каждый длиннее порога) и предел размера тела проверяются при создании.",
					"input": "Request",
					"output": "Response",
					"source": {
						"file": "packages/service/src/handler.ts",
						"line": 215
					}
				},
				{
					"id": "d-secret",
					"kind": "decision",
					"title": "Секрет верен?",
					"fn": "sameDigest",
					"text": "Authorization: Bearer. Сравниваются SHA-256 дайджесты, всегда со всеми секретами (время не зависит от того, какой подошёл), так что секрет можно ротировать списком.",
					"source": {
						"file": "packages/service/src/handler.ts",
						"line": 57
					}
				},
				{
					"id": "r401",
					"kind": "end-fail",
					"title": "401",
					"output": "problem+json, www-authenticate: Bearer",
					"text": "Ответ одинаков для любого маршрута: список маршрутов не раскрывается неавторизованным."
				},
				{
					"id": "d-route",
					"kind": "decision",
					"title": "Такой маршрут есть?"
				},
				{
					"id": "r404",
					"kind": "end-fail",
					"title": "404"
				},
				{
					"id": "d-method",
					"kind": "decision",
					"title": "Метод POST?"
				},
				{
					"id": "r405",
					"kind": "end-fail",
					"title": "405",
					"output": "allow: POST"
				},
				{
					"id": "d-size",
					"kind": "decision",
					"title": "Тело не больше предела?",
					"fn": "readLimited",
					"text": "Объявленная длина и поток считаются отдельно: заниженный Content-Length не поможет.",
					"source": {
						"file": "packages/service/src/handler.ts",
						"line": 91
					}
				},
				{
					"id": "r413",
					"kind": "end-fail",
					"title": "413"
				},
				{
					"id": "d-json",
					"kind": "decision",
					"title": "UTF-8 и JSON-объект?"
				},
				{
					"id": "r400",
					"kind": "end-fail",
					"title": "400",
					"text": "Неверный JSON, не объект, лишний ключ, неверный тип. Формы запросов закрытые (hasOnlyKeys)."
				},
				{
					"id": "route",
					"kind": "step",
					"title": "Маршрут разбирает тело",
					"text": "Проверка формы, затем вызов ядра: /v1/sign-in (фактор по id из списка через Object.hasOwn), /v1/sessions/verify, /v1/sessions/revoke, /v1/agents/delegate, /v1/agents/verify, /v1/meter/consume, /v1/meter/observe, /v1/identities/delete."
				},
				{
					"id": "core",
					"kind": "jump",
					"title": "Ядро решает",
					"text": "Любой отказ предметной области это обычный ответ.",
					"jump": {
						"flow": "map",
						"node": "surface"
					}
				},
				{
					"id": "r200",
					"kind": "end-ok",
					"title": "200 JSON",
					"output": "{ ok: true, value } | { ok: false, error }",
					"text": "Отказ ядра (no-allow, invalid-session, rate-limited) приходит со статусом 200 и тем же видом, что в процессе."
				},
				{
					"id": "r500",
					"kind": "end-fail",
					"title": "500",
					"text": "Неожиданное исключение. Тело ответа не содержит причины."
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "d-secret",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-secret",
					"to": "r401",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-secret",
					"to": "d-route",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-route",
					"to": "r404",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-route",
					"to": "d-method",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-method",
					"to": "r405",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-method",
					"to": "d-size",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-size",
					"to": "r413",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-size",
					"to": "d-json",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-json",
					"to": "r400",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-json",
					"to": "route",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "route",
					"to": "r400",
					"label": "форма не та",
					"kind": "fail"
				},
				{
					"from": "route",
					"to": "core",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "core",
					"to": "r200",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "core",
					"to": "r500",
					"label": "исключение",
					"kind": "fail"
				}
			]
		},
		{
			"id": "service-client",
			"group": "Режим сервиса",
			"title": "Сервис: клиент",
			"summary": "Клиент отдаёт те же формы, что ядро в процессе. Главное правило: ничего неясное не становится разрешением. Сеть, таймаут, чужой статус или кривой ответ дают отказ unavailable, никогда успех.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "client.signIn / sessions.verify / ...",
					"fn": "createAuthClient(options)",
					"text": "Тот же поверхностный API, что у Auth: код приложения не знает, в процессе ядро или по сети.",
					"source": {
						"file": "packages/service/src/client.ts",
						"line": 238
					}
				},
				{
					"id": "call",
					"kind": "step",
					"title": "POST на сервис",
					"fn": "call",
					"text": "fetch с секретом, redirect: error (секрет не уйдёт на другой адрес), cache: no-store, таймаут. Повторов нет: consume и mutateIdentity не идемпотентны.",
					"source": {
						"file": "packages/service/src/client.ts",
						"line": 256
					}
				},
				{
					"id": "d-transport",
					"kind": "decision",
					"title": "Ответ получен?",
					"text": "Сетевая ошибка или таймаут: причина network | timeout."
				},
				{
					"id": "d-status",
					"kind": "decision",
					"title": "Статус 200?",
					"text": "401 и 403 это причина unauthorized; 5xx это server-error; любой другой статус это unexpected-status."
				},
				{
					"id": "d-body",
					"kind": "decision",
					"title": "Тело это JSON нужной формы?",
					"fn": "ask + parse*",
					"text": "Строгие разборщики: ok без value, error не код, неверные типы полей это причина malformed. Успех возможен только из правильно оформленного ответа 200.",
					"source": {
						"file": "packages/service/src/client.ts",
						"line": 298
					}
				},
				{
					"id": "unavailable",
					"kind": "end-fail",
					"title": "unavailable",
					"text": "Результаты возвращают fail(unavailable) (счётчик: { code: unavailable }). revoke бросает ошибку, которую узнаёт isUnavailableError: молча не отозвать хуже, чем упасть. Причину получает onUnavailable (логи, метрики), он не меняет исход.",
					"codes": [
						"unavailable"
					]
				},
				{
					"id": "domain",
					"kind": "end-fail",
					"title": "Отказ ядра",
					"text": "Ответ 200 вида { ok: false, error }: no-allow, invalid-session, rate-limited, step-up-required и так далее передаются как есть."
				},
				{
					"id": "ok",
					"kind": "end-ok",
					"title": "Успех ядра",
					"text": "{ ok: true, value } разобран строго."
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "call",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "call",
					"to": "d-transport",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-transport",
					"to": "unavailable",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-transport",
					"to": "d-status",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-status",
					"to": "unavailable",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-status",
					"to": "d-body",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-body",
					"to": "unavailable",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-body",
					"to": "domain",
					"label": "ok: false",
					"kind": "branch"
				},
				{
					"from": "d-body",
					"to": "ok",
					"label": "ok: true",
					"kind": "branch"
				}
			]
		},
		{
			"id": "startup",
			"group": "Запуск и инструменты",
			"title": "Запуск: createAuth",
			"summary": "Единая точка сборки ядра. Хук аудита один на все части: построить часть без него нельзя. Ошибки настройки бросаются здесь, при старте, до первого запроса.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "createAuth(options)",
					"fn": "createAuth",
					"input": "{ identities, epochs, tokenStore, meterStore, secrets, maximumLifeTimeMilliseconds, sessionTimeToLiveMilliseconds, stepUpTimeToLiveMilliseconds?, policy, audit }",
					"output": "Auth",
					"source": {
						"file": "packages/core/src/auth.ts",
						"line": 82
					}
				},
				{
					"id": "d-audit",
					"kind": "decision",
					"title": "audit это функция?",
					"text": "Аудит обязателен намеренно. Не нужен вам: передайте приёмник, который ничего не делает.",
					"throws": "TypeError"
				},
				{
					"id": "d-ttl",
					"kind": "decision",
					"title": "Срок сессии не больше максимального?",
					"text": "Раньше это бросало бы на первом входе; теперь при старте.",
					"throws": "RangeError"
				},
				{
					"id": "throw",
					"kind": "end-fail",
					"title": "Исключение при старте",
					"text": "Приложение не запускается: лучше упасть сразу, чем узнать о неверной настройке, когда кто-то входит.",
					"codes": [
						"TypeError",
						"RangeError"
					]
				},
				{
					"id": "sealer",
					"kind": "step",
					"title": "createSealer",
					"text": "Секреты: хотя бы один, версии без повторов, длина не меньше порога, первый запечатывает, любой расшифровывает.",
					"throws": "RangeError",
					"source": {
						"file": "packages/core/src/sealer.ts",
						"line": 216
					}
				},
				{
					"id": "tokens",
					"kind": "step",
					"title": "createTokens",
					"source": {
						"file": "packages/core/src/tokens/tokens.ts",
						"line": 52
					}
				},
				{
					"id": "meter",
					"kind": "step",
					"title": "createMeter",
					"source": {
						"file": "packages/core/src/meter/meter.ts",
						"line": 128
					}
				},
				{
					"id": "session-tokens",
					"kind": "step",
					"title": "createSessionTokens",
					"text": "Принимает sealer и хранилище эпох; максимум срока токена.",
					"throws": "RangeError",
					"source": {
						"file": "packages/core/src/session-tokens/session-tokens.ts",
						"line": 282
					}
				},
				{
					"id": "mutate",
					"kind": "step",
					"title": "createMutateIdentity",
					"source": {
						"file": "packages/core/src/identity/mutate-identity.ts",
						"line": 77
					}
				},
				{
					"id": "sign-in",
					"kind": "step",
					"title": "createSignIn",
					"text": "Срок сессии и срок продолжения step-up превращаются в Duration; плохое число бросает RangeError.",
					"throws": "RangeError",
					"source": {
						"file": "packages/core/src/sign-in.ts",
						"line": 173
					}
				},
				{
					"id": "auth",
					"kind": "end-ok",
					"title": "Auth",
					"output": "{ signIn, sessions: { verify, revoke }, agents: { delegate, verify }, tokens, meter, sealer, mutateIdentity }",
					"text": "Строительные блоки (issueSession, verifyProof, evaluatePolicy...) в публичный API не входят и не попадают в пакет."
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "d-audit",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-audit",
					"to": "throw",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-audit",
					"to": "d-ttl",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "d-ttl",
					"to": "throw",
					"label": "нет",
					"kind": "fail"
				},
				{
					"from": "d-ttl",
					"to": "sealer",
					"label": "да",
					"kind": "branch"
				},
				{
					"from": "sealer",
					"to": "tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "tokens",
					"to": "meter",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "meter",
					"to": "session-tokens",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "session-tokens",
					"to": "mutate",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "mutate",
					"to": "sign-in",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "sealer",
					"to": "throw",
					"label": "плохие секреты",
					"kind": "fail"
				},
				{
					"from": "sign-in",
					"to": "auth",
					"label": "",
					"kind": "ok"
				}
			]
		},
		{
			"id": "doctor",
			"group": "Запуск и инструменты",
			"title": "Доктор",
			"summary": "CLI для CI и локальной проверки: гоняет пробы на ваших хранилищах и факторах и печатает минимальный сценарий взлома для каждой находки. Пишет только ключи с префиксом vow-doctor-, запускайте на тестовом окружении.",
			"nodes": [
				{
					"id": "start",
					"kind": "start",
					"title": "vow-auth-doctor <модуль>",
					"fn": "main(argv, print)",
					"text": "Модуль экспортирует по умолчанию { options, factors?, suppress? } или функцию, которая это возвращает.",
					"output": "код выхода",
					"source": {
						"file": "packages/doctor/src/cli.ts",
						"line": 48
					}
				},
				{
					"id": "load",
					"kind": "step",
					"title": "Загрузить модуль",
					"fn": "load",
					"source": {
						"file": "packages/doctor/src/cli.ts",
						"line": 26
					}
				},
				{
					"id": "not-run",
					"kind": "end-fail",
					"title": "выход 2",
					"text": "Нет аргумента, модуль не загрузился или форма не та. Прогона не было."
				},
				{
					"id": "run",
					"kind": "step",
					"title": "Прогнать пробы",
					"fn": "runDoctor",
					"text": "Каждая проба в try/catch: проба, которая бросила (хранилище недоступно), это находка, а не молчаливый пропуск.",
					"source": {
						"file": "packages/doctor/src/run-doctor.ts",
						"line": 41
					}
				},
				{
					"id": "checks",
					"kind": "step",
					"title": "Семь проб",
					"text": "config (createAuth принимает настройки), secrets (слабые секреты: мало разных символов, повтор, заготовки), token store (32 параллельных take отдают запись одному), epoch store (штампы строго растут), meter store (40 параллельных запросов при лимите 10), identity store (один субъект на идентичность, тенанты разделены), factors (отказ на пустое доказательство)."
				},
				{
					"id": "d-suppress",
					"kind": "decision",
					"title": "Находка в списке suppress?",
					"text": "Подавленные уходят из вердикта, но остаются в отчёте."
				},
				{
					"id": "report",
					"kind": "step",
					"title": "Отчёт",
					"fn": "formatReport",
					"text": "PASS / SKIP / ERROR. У каждой находки: заголовок, шаги «как это эксплуатируется», исправление, ключ подавления.",
					"source": {
						"file": "packages/doctor/src/format-report.ts",
						"line": 22
					}
				},
				{
					"id": "d-errors",
					"kind": "decision",
					"title": "Есть ошибки?"
				},
				{
					"id": "exit1",
					"kind": "end-fail",
					"title": "выход 1"
				},
				{
					"id": "exit0",
					"kind": "end-ok",
					"title": "выход 0"
				}
			],
			"edges": [
				{
					"from": "start",
					"to": "load",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "load",
					"to": "not-run",
					"label": "сбой",
					"kind": "fail"
				},
				{
					"from": "load",
					"to": "run",
					"label": "ок",
					"kind": "branch"
				},
				{
					"from": "run",
					"to": "checks",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "checks",
					"to": "d-suppress",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-suppress",
					"to": "report",
					"label": "да: в SKIP / нет: в находки",
					"kind": "branch"
				},
				{
					"from": "report",
					"to": "d-errors",
					"label": "",
					"kind": "ok"
				},
				{
					"from": "d-errors",
					"to": "exit1",
					"label": "да",
					"kind": "fail"
				},
				{
					"from": "d-errors",
					"to": "exit0",
					"label": "нет",
					"kind": "branch"
				}
			]
		}
	]
};
