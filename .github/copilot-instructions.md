# Copilot instructions

A NestJS + TypeScript + Postgres monorepo published as a **controls list, not a feature list**:
every capability maps to a named HIPAA / PCI-DSS v4.0.1 / SOC 2 control in `COMPLIANCE.md`, and
each is marked implemented or not.

`.claude/CLAUDE.md` is the full project memory and takes precedence over this file wherever the two
overlap. Read it before proposing anything structural.

## Code review

**Follow `.claude/skills/code-smell-audit/SKILL.md` when reviewing code, a diff, or a pull
request.** It is the review rubric for this repository, so do not substitute a generic checklist.
It defines the smell catalogue, and four things that matter more than the catalogue:

- **Rate every finding** by severity (Critical / Major / Minor / Trivial) and tag your confidence
  (Definite / Probable / Possible). An unrated finding is not actionable.
- **Check that the code is actually used before calling anything Critical.** Search for call sites
  first. If nothing reaches it, the primary smell is dead code and the fix is deletion; note the
  other problem only as "would matter if this were ever used". Overstating impact is the failure
  mode this rule exists to prevent.
- **On a diff or a PR, review only what the diff introduced or worsened.** Mention a pre-existing
  smell only where it interacts with the change.
- **Do not report what CI already catches.** ESLint, Prettier, `tsc`, the unit suite and
  `pnpm audit` all run on every PR, so repeating them is noise.

Fix order when several smells are present: change preventers, then couplers, then bloaters, then
dispensables, then object-orientation abusers.

## Non-negotiable, and not up for a suggestion

- **Clean-room. Original code only.** Nothing copied or adapted from any employer or client, ever.
  Everything is written from public specifications.
- **No secrets in the repo.** `.env.example` holds non-secret pointers only. Token keys are
  generated per deployment into the `config_keys` table by `pnpm keys:init`; the only key in
  configuration is `KEY_ENCRYPTION_KEY`, the KEK that wraps the rest.
- **Never overclaim compliance.** The kit is scaffolding that supports controls, not
  certification. Do not describe a capability as implemented without checking the Status column in
  `COMPLIANCE.md` first. Flag any wording in a diff that states an intention as a fact.
- **Tenant isolation is enforced by the database, not by application code.** One Postgres database
  per tenant, resolved through `ConnectionManager`. Do not propose a shared table with a
  `tenant_id` filter.
- **Verify library, API and regulatory claims against primary documentation.** Do not guess package
  names, config flags, SQL, or control numbers. A plausible citation is worse than none.
- **No em dashes in prose**, in code comments or in documentation.

## Things that look like bugs and are not

- **`packages/crypto` owns everything cryptographic**, including the Argon2id parameters and the
  nested-JWT codec. Never import `argon2` or `jose` from another package; the types that leak
  through are re-exported from `packages/crypto`.
- **Access tokens are nested JWTs**: signed with ES256, then encrypted with A256KW + A256GCM. Not
  HS256, because a symmetric inner signature lets anything that can verify also mint. No
  `@nestjs/jwt` or `passport-jwt`: the first is JWS-only, the second's token extractor is
  synchronous and cannot await a decryption.
- **The key resolvers handed to `jose` must stay synchronous.** jose calls them with an
  attacker-controlled `kid` before anything has been verified (RFC 8725 section 2.9), so making one
  `async` would let a forged kid drive a database query per unauthenticated request. Suggesting
  `await` there is a security regression, not a modernisation.
- **`verifyNestedToken` returns the headers alongside the claims on purpose.** They are obtainable
  no other way, because a decode-without-verify helper is the RFC 8725 section 2.3 mistake wearing
  a helpful name. Do not add one.
- **`config_keys.kid` is TEXT, not uuid.** RFC 7517 section 4.5 makes `kid` an arbitrary
  case-sensitive string, and a uuid column turns an attacker's non-uuid kid into a Postgres 22P02
  error, which is a 500 where it should be a 401.
- **TypeScript 6 with `module: "node20"`.** TypeScript 7 ships no programmatic compiler API, which
  `nest build` depends on. Do not change the module setting to `node16`; that reintroduces TS1479
  on the ESM-only `jose` import.
- **Prisma 7, not Drizzle.** Two schemas, two generated clients, one config file each
  (`packages/db/prisma.master.config.ts` and `prisma.tenant.config.ts`). The datasource `url`
  belongs in the config, never in the schema, which Prisma 7 rejects outright.
  `packages/db/sql/tenant-schema.sql` is generated but committed; regenerate it with
  `pnpm db:tenant-ddl` whenever the tenant schema changes.
- **Coverage thresholds reflect what is covered, not an aspiration.** The layers that talk to
  Postgres are deliberately not unit tested, because what makes them correct is database semantics
  a mock would only assert beliefs about. They run for real in CI. See `vitest.config.ts`.

## Commits

Subject in the imperative mood, body explaining why rather than what. No AI-attribution trailers.
