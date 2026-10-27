# Contributing

Thanks for taking the time. This page is short on purpose — everything here is something the CI will check anyway.

## Getting set up

Node 22.11+ and the pnpm that `packageManager` in `package.json` names (Corepack picks it).

```sh
pnpm install
pnpm test
```

## Before you push

`pnpm test` builds, checks the types and runs every test. The Postgres and Redis tests run only when their database is given:

```sh
VOW_AUTH_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
VOW_AUTH_REDIS_URL=redis://localhost:6379 \
pnpm test
```

CI also runs:

```sh
pnpm check   # Biome
pnpm knip    # unused files, exports and dependencies
pnpm audit
pip install semgrep==1.182.1
semgrep --test --metrics=off semgrep/                                # the rules against their own tests
semgrep scan --metrics=off --error --config semgrep/vow-auth.yml packages
```

## Comments

Comments other than JSDoc are stripped from code when it is committed (the `nocomments` git filter that `pnpm install` sets up, `scripts/strip-comments.mjs`). Directives stay: `@ts-…`, `biome-ignore`, and the Semgrep annotations `ruleid:`, `ok:` and `nosemgrep`.

## Where the decisions are

`docs/vision-review.md` holds the plan and the decisions; `docs/issuance.md` says who can issue access and which test holds each guarantee; each stage has its own document (`docs/stage-1-accounts.md`, `docs/stage-2-grants.md`, `docs/stage-3-oauth.md`).
