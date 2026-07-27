# CLAUDE.md — compliance-ready-backend-kit

Project memory for Claude Code. Read this before making changes. Local working memory
(who the user is, preferences) lives in `.claude/memory/` and loads automatically.

> **Current status and next steps live in `plan.md` (repo root, git-ignored).** Read it
> first, it records exactly where the build stands, what is verified, and what to do next.

## What this is

An open-source (MIT), **clean-room** compliance-ready backend kit: a NestJS + TypeScript
monorepo that gives teams an auditor-defensible backend baseline. The differentiator vs the
many NestJS boilerplates is that this is a **controls list, not a feature list** — every
capability maps to a named HIPAA / PCI-DSS v4.0.1 / SOC 2 control (see `COMPLIANCE.md`).
Goal: a **genuinely adopted OSS tool**, not a demo.

One-line pitch: *"The audit-ready NestJS baseline: passkeys, Postgres-enforced tenant
isolation, KMS envelope encryption, and append-only audit logs, each wired to the compliance
control your auditor will ask about."*

## Non-negotiable rules

- **Clean-room. Original code only.** No code copied or adapted from any employer (past or
  present) or client, ever. Everything is written from public specifications and standards.
  This is a hard line, not a preference.
- **No secrets in the repo.** `.env.example` holds non-secret pointers only (secret ARNs,
  endpoints). Real credentials are never committed. Secrets load at runtime from KMS /
  Secrets Manager into typed config; never read from `process.env` at runtime.
- **Never overclaim compliance.** The kit is *scaffolding that supports controls*, not
  certification. HIPAA / PCI / SOC 2 also require organizational policies, personnel
  controls, risk assessments, and formal third-party assessment. `COMPLIANCE.md` keeps the
  honest caveats (addressable != optional; PCI applies only inside the CDE; etc.).
- **Isolation is enforced by the database, not app code** (see multi-tenancy).

## Architecture

- **Monorepo** via pnpm workspaces. `services/` holds the deployable NestJS micro-services;
  `packages/` holds shared libraries (`config`, `db`, `common`, `crypto`).
- **`packages/crypto` owns everything cryptographic**: the Argon2id parameters and the
  nested-JWT codec. It exists because both the auth service and the tenant admin seed script
  need them, and two copies of a work factor or a token format eventually disagree. Never
  reach for `argon2` or `jose` from another package.
- **Node 24** is the target (current LTS line, "Krypton"). `.nvmrc` is the single source of
  truth: CI reads it via `actions/setup-node`'s `node-version-file`, so the two cannot drift.
- **TypeScript 6.0.3, and `module: "node20"`, not `commonjs`.** TS 7 is out but **cannot be
  used**: it ships no programmatic compiler API, and `nest build` / `nest start --watch` are
  built on `ts.createProgram`. TS 6 turns the legacy `moduleResolution: "node"` (node10) into
  a hard error, which is why the module setting moved to `node20`. That change is load-bearing
  twice over: it also lets a CommonJS build statically `import` the ESM-only `jose`, because
  TypeScript permits `require(esm)` when the module target is Node 20+. Do not "modernize" it
  to `node16`, which reintroduces TS1479 on the jose import.
- **Stack:** NestJS (Fastify adapter) + TypeScript (strict) + **Prisma 7** + Postgres + Redis.
  **ORM decision (2026-07-27): Prisma, not Drizzle.** An earlier session picked Drizzle for
  "explicit transaction / connection control". That reason is obsolete: Prisma 7 removed the
  Rust query engine and makes driver adapters mandatory, and `@prisma/adapter-pg`'s
  `PrismaPg` accepts an existing `pg.Pool` (verified in its shipped `.d.ts`:
  `constructor(poolOrConfig: pg.Pool | pg.PoolConfig | string, ...)`). We build the Pool, so
  pool sizing, lifetime, and error handling stay ours. Do not reintroduce Drizzle.
- **Two Prisma schemas, two generated clients.** `prisma/master/schema.prisma` migrates
  normally. `prisma/tenant/schema.prisma` has no single database, so it is rendered to
  `packages/db/sql/tenant-schema.sql` via `pnpm db:tenant-ddl` and applied at provisioning.
  That SQL is **generated but committed**; regenerate it whenever the tenant schema changes.
- **Prisma 7 gotchas** (all hit and fixed, do not re-litigate): datasource `url` is banned in
  the schema and lives in `prisma.config.ts`; `migrate diff` needs `--config` because the
  schema engine takes `--datasource` as a required argument; its path flags need the
  `--flag=value` form (space-separated silently yields an empty diff, exit 0).
- **Multi-tenancy = database-per-tenant.** A **master / config database** (control plane)
  holds the tenant registry and global config; each tenant gets its **own database** (data
  plane). The `ConnectionManager` in `packages/db` resolves a tenant, routes to its database,
  and provisions new ones. Stronger isolation than shared-table RLS, the right default for
  regulated workloads (you cannot keep two companies' data in one database).
- **Compliance mapping** lives in `COMPLIANCE.md`: feature -> HIPAA / PCI / SOC 2 control,
  fact-checked against eCFR / PCI SSC / AICPA TSC.

## Auth decisions (do not re-litigate)

- **Access tokens are nested JWTs: signed (JWS), then encrypted (JWE).** Inner HS256; outer
  A256KW + A256GCM with `cty: "JWT"`; two separate 256-bit keys, and config refuses to boot if
  they match. Implemented with `jose` directly, in `packages/crypto/src/tokens.ts`.
- **No `@nestjs/jwt`, no `@nestjs/passport`, no `passport-jwt`.** They were removed and must
  not come back: `@nestjs/jwt` wraps `jsonwebtoken`, which is JWS-only and cannot produce a
  JWE, and `passport-jwt` reads the token through a *synchronous* extractor that cannot await
  a decryption. `AccessTokenGuard` is a plain `CanActivate`.
- **Verify both layers, always.** `compactDecrypt` on its own is not verification (RFC 8725
  §2.3): the inner signature must be checked separately, or anyone with the encryption key can
  forge claims. Four smoke assertions guard this.
- **`typ` is `crbk-at+jwt`, never `at+jwt`.** RFC 9068 §2.1 makes `at+jwt` an assertion of
  conformance to a profile this kit does not meet (no `client_id`, no RS256 support).
- **The cross-tenant check lives inside `AccessTokenGuard`**, in the same step as
  authentication, and fails closed. It was originally a separate guard; that was wrong because
  a guard can be left out of a chain. A token for tenant A used with `x-tenant-id: B` must be
  rejected: db-per-tenant routes the query correctly, so no data crosses, but the caller would
  be acting inside a tenant they hold no account in, carrying A's permissions.
- **A tenant's first admin comes from a seed file** (`pnpm db:seed:admin`), not from
  provisioning and not from "first user to register wins". `/auth/register` is unauthenticated,
  so that shortcut is a land-grab race for anyone who learns a tenant slug.
- **`TenancyModule` and `AuthModule` are `@Global()`** so `@TenantAuthenticated` resolves its
  guards from any feature module. Without that, using the decorator means importing two modules
  in the right combination, which is the footgun the decorator exists to remove.

## v1 scope

**Auth + RBAC**, on the database-per-tenant + master-config-DB foundation. Deferred to later
milestones (keep a visible roadmap in `README.md`): passkeys / WebAuthn, OIDC, envelope
encryption, append-only audit log, rate limiting, OpenTelemetry, key rotation with `kid`, and
sender-constrained tokens (mTLS / DPoP).

## Conventions

- No AI-attribution trailers in commits. Commit as `faizahmedfarooqui <faizz.af@gmail.com>`.
- Verify library / API claims against primary docs before shipping. Do not guess package
  names, config flags, SQL, or regulatory control numbers.
- Companion write-ups live on faizahmed.in (multi-tenant SaaS, rate limiting, KMS secrets,
  idempotency, webhooks, observability). Cross-link each module to the post that explains it.
