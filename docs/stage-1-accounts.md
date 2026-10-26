# Этап 1. Аккаунты: схема, порт, поток входа

Статус: реализовано 2026-10-25. Решения 1–3 приняты. Чем код отличается от проекта — в конце документа.

## Что меняется

Сейчас человек — это субъект внутри тенанта, и идентичности принадлежат субъекту. Тот же человек в двух тенантах — два чужих друг другу субъекта с разными идентичностями.

Будет так:

- **Аккаунт** — человек в зоне данных (одно развёртывание). Идентичности (`google|123`, `email|ivan@x`) принадлежат аккаунту.
- **Субъект** — членство аккаунта в тенанте. Свой стабильный id на пару «аккаунт + тенант»; приложение, как и раньше, ставит внешние ключи на `vow_auth_subjects (id)`.
- **Тенант** — запись, которую создаёт приложение.

## Что входит в этап

1. Тенанты как записи: вход в несуществующий или отключённый тенант отвергается.
2. Аккаунт, идентичности у аккаунта, членства со стабильным id.
3. Новый порядок входа: всё, что меняет данные (создание, привязка, членство, вытеснение, обновление данных провайдера), — только после окончательного разрешения, включая step-up.
4. Политика регистрации: решает до создания аккаунта или членства.
5. `trustedProviders`: чья подтверждённая почта связывает аккаунты и считается подтверждённой.
6. Обновление данных провайдера при входе.
7. Запечатанные записи: строка, вставленная или изменённая в обход движка, входа не даёт.
8. Факторы видят аккаунт: TOTP хранится по аккаунту, один на все тенанты; удаление аккаунта стирает данные факторов.
9. Управление: удалить аккаунт; приостановить, исключить и вернуть членство; создать, отключить и включить тенант.

## Что не входит и где будет

| Что | Где | Почему не сейчас |
|---|---|---|
| Сессия аккаунта, разрешения, удаление штампов | Этап 2 | Сделано на этапе 2 (`docs/stage-2-grants.md`) |
| Попарный id | Этап 3 | Нужен только в токенах сторонним клиентам. По OIDC Core §8.1 он считается по sector identifier (хосту адресов возврата клиента), а не по `client_id`; это учтём там |
| Приглашения и метки ролей | После этапа 2 | Приглашение — вход в тенант из сессии аккаунта |
| Привязка новой идентичности из живой сессии и отвязка | На этапе 2 не сделано; перенесено в «Отложено» `docs/vision-review.md` | Для отвязки понадобится версия идентичностей в печати аккаунта, иначе удалённую строку можно вернуть её же копией |
| Телефон как идентификатор | Этап 5 | Вместе с фактором телефона |
| Признак «создано агентом» | Этап 6 | Вместе с агентами |

## Схема Postgres

```sql
create table if not exists vow_auth_tenants (
	id text primary key,
	created_at_milliseconds bigint not null default <now>,
	disabled_at_milliseconds bigint,
	seal text not null
);

create table if not exists vow_auth_accounts (
	id text primary key,
	-- null: личный аккаунт; позже — управляемый тенантом (вопрос 2 разбора)
	managed_by_tenant text references vow_auth_tenants (id),
	created_at_milliseconds bigint not null default <now>,
	evicted_at_milliseconds bigint,
	seal text not null
);

create table if not exists vow_auth_identities (
	seq bigserial not null,
	provider text not null,
	external_id text not null,
	account_id text not null references vow_auth_accounts (id) on delete cascade,
	email text,
	email_verified boolean not null,
	updated_at_milliseconds bigint not null default <now>,
	seal text not null,
	primary key (provider, external_id)
);
create index if not exists vow_auth_identities_account on vow_auth_identities (account_id);
create index if not exists vow_auth_identities_email on vow_auth_identities (email, seq) where email is not null;

create table if not exists vow_auth_subjects (
	id text primary key,
	tenant text not null references vow_auth_tenants (id),
	account_id text references vow_auth_accounts (id) on delete set null,
	status text not null check (status in ('active', 'suspended', 'removed')),
	created_at_milliseconds bigint not null default <now>,
	seal text not null,
	unique (tenant, account_id)
);

-- vow_auth_tokens — без изменений
```

- Идентичность уникальна в зоне: `(provider, external_id)` без тенанта.
- Внешние ключи приложения — на `vow_auth_subjects (id)`, как раньше.
- Id: `acc_` и `sub_` плюс 32 шестнадцатеричных знака (128 бит). Id тенанта выбирает приложение.
- Миграции нет: ветка не выпускалась, схема заменяется.

## Порт хранилища

```ts
type StoredTenant = { readonly id: string; readonly disabled: boolean; readonly seal: string };

type StoredAccount = {
	readonly id: string;
	readonly managedByTenant: string | undefined;
	readonly evicted: boolean;
	readonly seal: string;
};

type StoredIdentity = {
	readonly provider: string;
	readonly externalId: string;
	readonly accountId: string;
	readonly email: string | undefined;
	readonly emailVerified: boolean;
	readonly seal: string;
};

type MembershipStatus = "active" | "suspended" | "removed";

type StoredMembership = {
	readonly subjectId: string;
	readonly tenant: string;
	/** `undefined` once the account was deleted: the row stays for the application's foreign keys. */
	readonly accountId: string | undefined;
	readonly status: MembershipStatus;
	readonly seal: string;
};

/**
 * Every write is atomic. `create*` and `linkIdentity` are first-wins: on a
 * conflict nothing changes and the call says so. `set*` and `updateIdentity`
 * are compare-and-set on the seal the caller read: a row changed in between
 * is left alone. The seal is opaque to the store.
 */
type AccountStore = {
	getTenant(id: string): Promise<StoredTenant | undefined>;
	createTenant(tenant: StoredTenant): Promise<"created" | "conflict">;
	setTenant(tenant: StoredTenant, expectedSeal: string): Promise<boolean>;

	findIdentity(provider: string, externalId: string): Promise<StoredIdentity | undefined>;
	/** The oldest identity of one of `providers` that verified the email. */
	findVerifiedOwner(email: string, providers: readonly string[]): Promise<StoredIdentity | undefined>;
	getAccount(id: string): Promise<StoredAccount | undefined>;
	findMembership(tenant: string, accountId: string): Promise<StoredMembership | undefined>;
	getMembership(tenant: string, subjectId: string): Promise<StoredMembership | undefined>;
	listMemberships(accountId: string): Promise<readonly StoredMembership[]>;

	/** Account, its first identity and, when given, its first membership, in one statement. */
	createAccount(
		account: StoredAccount,
		identity: StoredIdentity,
		membership: StoredMembership | undefined,
	): Promise<"created" | "conflict">;
	/** Only into an account that exists and is not evicted. */
	linkIdentity(identity: StoredIdentity): Promise<"linked" | "conflict" | "missing">;
	updateIdentity(identity: StoredIdentity, expectedSeal: string): Promise<boolean>;
	createMembership(membership: StoredMembership): Promise<"created" | "conflict">;
	setMembership(membership: StoredMembership, expectedSeal: string): Promise<boolean>;

	/**
	 * In one statement: removes every claim of the email that is not verified
	 * by one of `trustedProviders` from every account except `keepAccountId`,
	 * marks the accounts left without identities evicted, and returns every
	 * account it touched.
	 */
	evictEmailClaims(
		email: string,
		keepAccountId: string,
		trustedProviders: readonly string[],
	): Promise<readonly string[]>;
	/** Deletes the account and its identities; its memberships stay, with no account and status `removed`. */
	deleteAccount(id: string): Promise<readonly StoredMembership[] | undefined>;
};
```

Порт `IdentityStore` уходит; адаптеры памяти и Postgres и контрактные тесты переписываются под `AccountStore`.

## Поток входа

```
1. Фактор проверяет ответ → доказательство.                          (как сейчас)
2. Чтение, без записи — план:
   а. идентичность (provider, externalId) есть → её аккаунт;
   б. нет, почта подтверждена и провайдер доверенный → аккаунт-владелец почты → «привязать»;
   в. иначе → «новый аккаунт» (id выбран заранее);
   г. членство аккаунта в тенанте: активно → оно; приостановлено → отказ;
      исключено → «вернуть»; нет → «новое членство» (id выбран заранее);
   д. тенант существует и не отключён.
   Печать каждой прочитанной записи проверяется; не сходится → отказ.
3. Политика регистрации — если план создаёт аккаунт, членство или возвращает его.
4. Политика входа → разрешить, step-up или отказ. При step-up ничего не записано.
5. Только теперь записи: создать или привязать, членство, данные провайдера,
   вытеснение неподтверждённых претензий на эту почту. Проиграли гонку → отказ «conflict».
6. Сессия.
```

**Пример.** У Ивана аккаунт `acc_1` с идентичностью `email|ivan@x` и членством в globex. Он впервые входит в acme через Google; Google говорит, что `ivan@x` подтверждена; `trustedProviders = ["email", "google"]`.

1. Доказательство `google|123`, `ivan@x`, подтверждена.
2. Идентичности `google|123` нет; Google доверенный; владелец `ivan@x` — `acc_1`. План: привязать `google|123` к `acc_1` и создать членство `sub_a` в acme.
3. Политика регистрации: новое членство в acme — разрешено.
4. Политика acme требует TOTP — step-up. В базе ничего не изменилось.
5. TOTP видит `account: acc_1` и проверяет код Ивана (один на все тенанты).
6. Обе политики ещё раз, со всеми доказательствами, — разрешено.
7. Записи: привязка, членство `sub_a`, вытеснение чужих неподтверждённых претензий на `ivan@x`. Сессия acme/`sub_a`.

Если на шаге 5 код неверный — нет ни привязки, ни членства, ни вытеснения. Сейчас вытеснение и создание субъекта происходят до политики; этап 1 это исправляет.

Если Google не доверенный, на шаге 2 план — новый аккаунт, а подтверждённая Google почта считается неподтверждённой. Политика регистрации видит флаг `emailOwnedByAnotherAccount` и может отказать с подсказкой «войдите тем способом, которым входили раньше».

**Второй шаг step-up.** Второе доказательство должно точно повторять утверждения первого (как TOTP) или указывать на идентичность того же аккаунта. План пересчитывается по первому доказательству на втором шаге: данные могли измениться между шагами.

## `trustedProviders`

- Параметр `createAuth`, по умолчанию `["email"]`: подтверждённость почты своим фактором ссылки.
- Каждый провайдер списка должен быть объявлен каким-то зарегистрированным фактором, иначе ошибка при запуске.
- Действует в двух местах: связывание по подтверждённой почте и «кто владелец почты». Подтверждённая почта от недоверенного провайдера считается неподтверждённой: она не делает владельцем и вытесняется настоящим владельцем.

Закрываемая атака: провайдер, которому не доверяем, говорит «`victim@x` подтверждена», злоумышленник создаёт аккаунт, а потом жертва входит по ссылке и попадает в его аккаунт. С правилом выше жертва получает свой аккаунт, а претензия злоумышленника вытесняется.

## Печать записей

- HMAC-SHA-256. Ключ выводится HKDF из секретов в своём домене (`vow-auth/record/v1/`), отдельно от печати значений (`vow-auth/seal/v1/`). Фактор и приложение этого ключа не получают.
- Формат печати: `<версия секрета>.<base64url>`. Печать проверяется по версии из записи.
- Что запечатано:

| Запись | Поля в печати |
|---|---|
| Тенант | id, отключён ли |
| Аккаунт | id, кем управляется |
| Идентичность | provider, externalId, аккаунт, почта, подтверждена ли |
| Членство | id, тенант, аккаунт, статус |

- Печать — заодно и метка версии для compare-and-set: поменялось любое поле — поменялась печать.
- Не сходится → отказ во входе и запись аудита `invalid-record`; запись не считается отсутствующей, чтобы подделка не превращалась в новый аккаунт.
- Вытеснение ставит `evicted_at` одним SQL-оператором и печать не обновляет. Это безопасно: вытесненный аккаунт уже без идентичностей, а вставить идентичность без печати нельзя. Стереть `evicted_at` — значит вернуть пустой аккаунт, в который нечем войти.
- **Ротация.** Запись, запечатанная старой версией, перепечатывается новой при ближайшем входе. Пока остались записи на старой версии, удалять её из списка секретов нельзя: такие записи перестанут открываться. Пакетная перепечатка — до первого выпуска, в сквозной дорожке.
- **Что печать не закрывает.** Удаление строк (отказ в обслуживании) и возврат удалённой строки её же копией. Второе станет важно с отвязкой идентичностей (этап 2) и закрывается версией идентичностей в печати аккаунта.

## Публичный API

- `createAuth`:
  - `identities` → `accounts: AccountStore`;
  - новое `registration: (input) => unknown`: `"allow"` разрешает, всё остальное — отказ;
  - новое `trustedProviders?: readonly string[]`.
- `RegistrationPolicyInput`: `{ tenant, proof, proofs, account, subject, newAccount, newMembership: "created" | "rejoined" | undefined, emailOwnedByAnotherAccount }`.
- `SignInPolicyInput` получает `account`.
- `SignedIn` получает `account` и `membership: "existing" | "created" | "rejoined"`.
- `FactorContext`: `{ tenant, account?, proofs }` вместо `subject`; у фактора — необязательный `forget(account)`, его вызывает удаление аккаунта.
- TOTP: `begin({ account, label })`, `confirm({ account, code })`, `renewBackupCodes({ account })`, `remove({ account })`; хранилище по аккаунту.
- `Auth.mutateIdentity` уходит; вместо него:
  - `auth.accounts.delete(account)`;
  - `auth.memberships.suspend | restore | remove(tenant, subject)`;
  - `auth.tenants.create | disable | enable(id)`.

  Каждая операция отзывает затронутые сессии и пишет аудит.
- Новые коды ошибок: `no-tenant`, `suspended`, `conflict`, `invalid-record`.

## Тесты — свойства этапа

1. Один человек в двух тенантах — один аккаунт, одна идентичность, два субъекта с разными id.
2. Исключили и вернули в тенант — тот же id субъекта.
3. Политика регистрации отказала — в хранилище не появилось ни одной строки.
4. Политика входа отказала или step-up не пройден — нет ни привязки, ни членства, ни вытеснения, ни нового аккаунта.
5. Вытеснение — только после окончательного разрешения и по всей зоне; сессии вытесненных отозваны во всех их тенантах.
6. Связывание по почте — только для доверенных провайдеров; подтверждённая почта недоверенного провайдера не делает владельцем и вытесняется.
7. Данные провайдера обновляются при входе и перепечатываются.
8. Строка, вставленная или изменённая в базе напрямую (память и Postgres), — отказ `invalid-record`; перенос идентичности или членства в чужой аккаунт — отказ.
9. Несуществующий или отключённый тенант — отказ; приостановленное членство — отказ `suspended`.
10. Удаление аккаунта — нет идентичностей и данных факторов; субъекты остаются без аккаунта и не дают входа; сессии отозваны.
11. Две одновременные первые попытки входа одной идентичностью — один аккаунт; проигравшая получает `conflict` или тот же аккаунт.
12. Второй фактор не может указать на другой аккаунт.
13. TOTP, подключённый в одном тенанте, работает во всех тенантах аккаунта.

## Решения (приняты)

1. **Тенант создаётся явно** (`auth.tenants.create`), вход в неизвестный тенант отвергается. Рекомендую: да. Иначе любой запрос с произвольным id создаёт «тенант-призрак», а издателю на тенанта (этап 3) нужна запись. Цена для приложения с одним тенантом — одна строка при установке.
2. **Политика регистрации обязательна**, как политика входа и аудит. Открытая регистрация — `registration: () => "allow"`. Рекомендую: да, решение нельзя забыть.
3. **Удаление аккаунта.** Субъекты остаются строками без аккаунта: данные приложения не ломаются, человека за ними нет, приложению возвращается список субъектов для своей чистки. Другой вариант — удалять и субъекты, тогда судьбу данных решает правило `on delete` внешнего ключа приложения. Рекомендую первое: так же устроено вытеснение.

## Чем код отличается от проекта

- В порте два метода сверх проекта: `setAccount` (перепечатка аккаунта; отметку вытеснения не меняет) и `findEmailClaimants` (кто претендует на почту, чтобы отозвать их сессии до вытеснения).
- План принимает только доказательство, отчеканенное `verifyProof`, как раньше `resolveIdentity`; подделка — отказ `no-proof`.
- Членство с аккаунтом в чужом поле (запись подменили) — тоже `invalid-record`.
- Если аудит недоступен во время изменения, которое отнимает доступ (приостановить, исключить, удалить), сессии уже отозваны, а запись не изменена; вызов падает с ошибкой аудита. Изменение, которое возвращает доступ, при недоступном аудите не делается вовсе.
- HTTP после входа отдаёт ещё `account` и `membership` — своему приложению, по решению о трёх идентификаторах.

## Где проверено

| Свойство | Тест |
|---|---|
| 1. Один человек в двух тенантах | `core/tests/a9-a10-accounts.test.ts`, `a3-a5-resolve-identity.test.ts` (A5) |
| 2. Тот же id субъекта после возврата | `a9-a10-accounts.test.ts` |
| 3. Отказ регистрации ничего не пишет | `a9-a10-accounts.test.ts` |
| 4. Отказ или незавершённый step-up ничего не пишут | `a9-a10-accounts.test.ts` |
| 5. Вытеснение после разрешения и по всей зоне | `a9-a10-accounts.test.ts` (A9), `a2-a14-sign-in.test.ts` |
| 6. Только доверенные провайдеры | `a9-a10-accounts.test.ts`, `a3-a5-resolve-identity.test.ts` (A3) |
| 7. Данные провайдера обновляются | `a9-a10-accounts.test.ts` |
| 8. Подделанные строки | `a9-a10-accounts.test.ts` |
| 9. Тенант и приостановленное членство | `a9-a10-accounts.test.ts`, `a2-a14-sign-in.test.ts` |
| 10. Удаление аккаунта | `a9-a10-accounts.test.ts` (A10), `factor-totp/tests/totp.test.ts`, `adapter-postgres/tests/postgres.integration.test.ts` |
| 11. Одновременные первые входы | `a9-a10-accounts.test.ts`, `a3-a5-resolve-identity.test.ts`, Postgres — `postgres.integration.test.ts` |
| 12. Второй фактор не указывает на другой аккаунт | `a2-step-up.test.ts` |
| 13. TOTP во всех тенантах аккаунта | `factor-totp/tests/totp.test.ts` |
| Контракт хранилища (память и Postgres) | `store-contracts/src/account-store-contract.ts` |
| Ротация секрета | `a9-a10-accounts.test.ts` |
