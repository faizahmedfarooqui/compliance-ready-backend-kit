# Contributing

Thanks for considering a contribution. This is a compliance-oriented project, so the bar
for a few specific things is higher than usual. Everything below explains why, so you can
argue with the reasoning rather than just follow rules.

## The clean-room rule

**All code here is original, written from public specifications and standards.**

Do not contribute code copied or adapted from an employer, a client, a private codebase,
or any source whose licence does not permit it. This is not a style preference: a single
tainted contribution puts every downstream user of an MIT-licensed compliance tool at
risk, and it cannot be quietly undone later.

By opening a pull request you confirm that the work is yours to give under the MIT licence.
If you are reimplementing something you have built before under an employment agreement,
write it from the public spec rather than from memory of that code.

Public specs, RFCs, standards documents, and official library documentation are all fair
game. That is where the rest of this repository came from.

## Verify claims against primary sources

The value of this project is that its assertions are true. So:

- **Regulatory citations** are checked against the primary text: eCFR for HIPAA, the PCI
  SSC standard for PCI-DSS, the AICPA Trust Services Criteria for SOC 2. Not a blog post,
  not a vendor comparison page, not an LLM.
- **Library and API claims** are checked against official documentation for the version in
  the lockfile, and preferably against the shipped type definitions.
- **Security-relevant behaviour** is checked by running it, not by reasoning about it.

If you cannot verify something, say so in the pull request and mark it explicitly rather
than presenting it as settled. A flagged uncertainty is useful. A confident wrong claim in
a compliance tool is actively harmful, and it is the fastest way to lose a reader's trust
in everything else in the repository.

When you touch [COMPLIANCE.md](./COMPLIANCE.md), cite the specific control number and
quote enough of the source to make the mapping checkable. Note whether a HIPAA
specification is Required or Addressable. Addressable does not mean optional.

## Never overclaim compliance

The kit is scaffolding that supports controls. It does not make anyone compliant, and no
document here should imply otherwise. Do not add language like "HIPAA compliant",
"SOC 2 certified", or "meets PCI-DSS". Prefer "supports", "helps satisfy", or "maps to".

Equally: **do not hide gaps.** The README's Status section exists to be honest about what
is missing. If your change reveals a new gap, add it there in the same pull request. A
documented weakness is a feature of a compliance tool. An undocumented one is a liability.

**Never name a capability the kit does not have.** This is the failure mode to watch, because it
happens through enthusiasm rather than dishonesty. Earlier versions of this repository described
itself as "the audit-ready NestJS baseline" and pitched "passkeys, KMS envelope encryption, and
append-only audit logs" while none of those three existed, and the control mapping listed thirteen
capabilities with no way to tell a shipped one from an intention.

So, concretely:

- [COMPLIANCE.md](./COMPLIANCE.md) has a **Status** column. Check it before writing marketing copy
  anywhere, including the README headline, the `package.json` description, and commit messages.
- When you implement a control, move its status in the same pull request. When you add a *row* for
  something not built, it starts at "Not implemented".
- Roadmap items belong in the roadmap, phrased as intentions. "The kit will support X" is fine.
  "The kit supports X" is not, until it does.

## Getting set up

Node 24 (the current LTS line, pinned in `.nvmrc`), pnpm 9, Docker.

**On an Intel Mac you also need the Xcode Command Line Tools.** `argon2` 0.45 ships prebuilt
binaries for darwin-arm64, linux-x64/arm64/arm, freebsd, and win32-x64, but **not** darwin-x64,
so `pnpm install` compiles it from source there via `node-gyp`. Apple Silicon, Linux, and
Windows are unaffected. This path is untested by the maintainer, who is on arm64: if you hit it,
a report either way is welcome.

```bash
nvm use                 # reads .nvmrc
cp .env.example .env
pnpm install
pnpm infra:up
pnpm db:migrate
pnpm build
```

Before opening a pull request, run what CI runs:

```bash
pnpm build              # MUST come first, see below
pnpm typecheck          # must pass clean, strict mode, no warnings suppressed
pnpm db:tenant-ddl      # must produce no diff, see "Changing a database schema"
pnpm start:auth &       # then, in another shell:
pnpm smoke              # all checks must pass
```

`pnpm build` has to run before `pnpm typecheck`, and the order is not cosmetic. Workspace
packages resolve each other through their `package.json` `"main"`/`"types"`, which point into
`dist/`, and `dist/` is gitignored. On a fresh clone nothing has been emitted yet, so
typechecking first fails with `Cannot find module '@compliance-kit/common'` in every package
that imports a sibling. Building emits the declaration files typecheck then resolves against.

`.nvmrc` is the single source of truth for the Node version: CI reads it via
`actions/setup-node`'s `node-version-file`, so bumping the Node version is a one-line
change and CI cannot drift from local development.

`pnpm smoke` provisions **real** tenant databases named `tenant_smoke_*`, because provisioning a
real database is one of the things it exists to prove. Two per run, and it does not clean up
after itself, so they accumulate:

```bash
pnpm clean:test-tenants          # dry run: lists what it would drop
pnpm clean:test-tenants --yes    # actually drop them
```

It only ever touches databases whose names match a known test prefix, and it scans `pg_database`
rather than the tenant registry so it also catches databases orphaned by an interrupted
provisioning run. `pnpm infra:reset` is the bigger hammer: it destroys the whole volume.

### Stopping the server, and why by port

Use `pnpm stop:auth` (or `pnpm restart:auth`). It kills whatever is **listening on the port**,
not whatever matches a process name.

That distinction is not pedantry. `nest start --watch` runs the app as
`node --enable-source-maps <abs path>/dist/main`, with no `.js`, so a reasonable-looking
`pkill -f "node dist/main.js"` matches nothing and exits successfully. The stale server keeps
the port, your freshly built one dies with `EADDRINUSE`, and the test suite you then run is
talking to the old build. This happened during development and produced a full green run
against code that was not under test.

Two things now catch it: `stop:auth` kills by port, and `pnpm smoke` opens by asking
`GET /api/health` which version it is talking to and how long that process has been up. Set
`SMOKE_MAX_UPTIME` (seconds, default 1800) if you are deliberately testing a long-lived server,
or `0` to skip the check.

### Seeding a tenant administrator

Provisioning a tenant creates its database and RBAC catalogue but no users, so a fresh
tenant has nobody who can log in. Grant the first administrator with the seed file:

```bash
SEED_ADMIN_PASSWORD='...' pnpm db:seed:admin --tenant acme --email admin@acme.example
```

Prefer the environment variable over `--password`, which lands in your shell history. The
script is idempotent: re-running it for an existing user grants the role without touching
the password, so it is also the way to repair a tenant that has lost its administrator.

This is deliberately not an HTTP endpoint and deliberately not part of provisioning.
Creating infrastructure and granting a human administrative access are separate decisions,
and an access review wants to see them as separate events.

### Changing a database schema

The two Prisma schemas are handled differently, and it is easy to get this wrong:

- **Master schema** (`packages/db/prisma/master/schema.prisma`): generate a migration with
  `pnpm db:migrate:dev` and commit it.
- **Tenant schema** (`packages/db/prisma/tenant/schema.prisma`): there is no single
  database to migrate, so run `pnpm db:tenant-ddl` to regenerate
  `packages/db/sql/tenant-schema.sql` and **commit the regenerated SQL**. That file is
  what runs against every new tenant database.

A tenant schema change without the regenerated SQL is a change that silently does nothing
for new tenants. Existing tenant databases are not migrated at all yet; a per-tenant
migration runner is on the roadmap, and until then a tenant schema change is only safe
before you have tenants you care about.

### Changing how passwords are hashed

Argon2 parameters live in exactly one place, `packages/crypto/src/passwords.ts`, because two
consumers depend on them: the auth service and the tenant admin seed script. Do not add a
second copy, and do not reach for `argon2` directly from another package.

If you raise the work factor, you do not need to migrate anything: existing hashes are
detected via `needsRehash` and upgraded transparently on the owner's next successful login,
which is the only moment the plaintext is available.

### Changing the access token

`packages/crypto/src/tokens.ts` is the only place tokens are issued or verified. They are
nested JWTs: signed, then encrypted. If you touch it, four properties are load-bearing and
each has a smoke-test assertion behind it. Do not "simplify" any of them away:

1. **Sign, then encrypt** (RFC 7519 §11.2), never the reverse.
2. **Verify both layers.** `compactDecrypt` alone is not verification: without the separate
   `jwtVerify`, anyone holding the encryption key could encrypt a claims set of their choosing
   and have it accepted (RFC 8725 §2.3). This is the single easiest thing to get wrong.
3. **`cty: "JWT"` on the outer JWE**, set and checked. jose does neither for you.
4. **Two different keys.** Config refuses to boot if the signing and encryption keys match.

Algorithms are allow-listed on the way in rather than read from the token's own header, so a
token cannot nominate a weaker algorithm than the one we require. Compressed JWEs are
rejected outright (`maxDecompressedLength: 0`, RFC 8725 §3.6).

To inspect a token during development:

```bash
node scripts/decode-token.mjs "$TOKEN"
```

That performs the full two-layer verification, so it fails on a token that decrypts but does
not verify. It is not a decoder.

### Adding an error, or an endpoint that can fail

Errors are [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem Details and successes are
`{ success, data, meta }`. Both shapes are produced centrally, so a handler should just throw a
`DomainError` or return a resource, and never build a response body itself.

To add a problem type:

1. Add a `DomainError` subclass in `packages/common/src/index.ts`. It takes `(title, message,
   code)`. Keep `title` **stable and free of request data**: RFC 9457 §3.1.3 says it should not
   change between occurrences, so the tenant slug or field name goes in `message`, which becomes
   `detail`.
2. Map the code to a status in `STATUS_BY_ERROR` in
   `services/auth/src/common/problem-details.filter.ts`. Unmapped domain errors fall back to 400.
3. Document it in [problems.md](./problems.md) under a heading whose anchor is the
   code in kebab-case. The `type` URI is derived from the code, so a missing section means the
   URI points at a heading that does not exist. The smoke test checks this.
4. Add a smoke-test assertion.

Do not add a fourth response shape. Do not use `HttpException` in a controller or service where
a `DomainError` would do; `HttpException` is normalised into the same shape, but it puts the HTTP
concern in the wrong layer.

If a route needs to return metadata alongside its resource, return `withMeta(payload, { ... })`
rather than reshaping the body:

```ts
return withMeta(users, { totalCount: 412, nextItem: cursor });
```

### Adding a permission

Add it to `PERMISSION_KEYS` and `DEFAULT_PERMISSIONS` in
[packages/common/src/index.ts](packages/common/src/index.ts). Both, in the same commit.
The first makes it usable in `@TenantAuthenticated`; the second seeds it into new tenant
databases. Adding only the first gives you a route nobody can ever call.

### Adding a tenant-scoped route

Use `@TenantAuthenticated(...)`, not a hand-assembled `@UseGuards(...)` chain. The guard
order is load-bearing and the decorator exists so it cannot be got wrong. If you find
yourself needing a different chain, that is worth discussing in an issue first.

## Pull requests

- One logical change per pull request. A refactor bundled with a behaviour change is hard
  to review and harder to revert.
- Explain **why**, not just what. The diff already shows what.
- Match the surrounding code: the comment density here is deliberately high, and comments
  explain reasoning and trade-offs rather than restating the line below them.
- Say what you verified and how, including what you could not verify.
- If you change security-relevant behaviour, add a check to `scripts/smoke-test.sh`. The
  cross-tenant token check in step 12 exists because that bug was found by running the smoke
  test, and it stays there so it cannot come back.
- No AI-attribution trailers in commit messages.

## Adding or upgrading a dependency

The runtime dependency closure is part of what an assessor reviews, so it is kept small and
deliberate on purpose: the auth service has 12 runtime dependencies, and `packages/crypto`
brings in `jose`, which has none of its own. Prefer adding nothing.

If you do add or upgrade something:

- **Check the whole closure, not just the package.** Upgrading `argon2` to 0.45 also added
  `cross-env`, `cross-spawn`, and `@epic-web/invariant` behind it, because its install step now
  shells out to `cross-env`. That is three packages a reader of `package.json` would not see.
- **Verify the version against primary docs**, not a changelog summary. The `argon2` 0.45 rename
  of `Options` to `HashOptions` appears in no release note; it was only visible in the shipped
  `.d.ts`.
- **Regenerate and commit `pnpm-lock.yaml` in the same change.** CI runs
  `pnpm install --frozen-lockfile`, so a manifest edit without the lockfile fails the build
  before any test runs.
- Note that a caret on a `0.x` version does not cross the minor: `^0.14.1` can never install
  `0.15.0`. This had quietly pinned `class-validator` for a while.

## Style

TypeScript strict, no `any` without a comment justifying it, no non-null assertions where a
narrowing check would do. Comments explain reasoning; code explains mechanics. Prefer
making an invariant unrepresentable over documenting it.

Text is written in plain prose. Avoid em dashes.

## Reporting bugs

Open an issue with the version or commit, what you expected, what happened, and the
smallest reproduction you can manage. If it is a security problem, do not open an issue:
see [SECURITY.md](./SECURITY.md).

## Licence

Contributions are accepted under the [MIT licence](./LICENSE).
