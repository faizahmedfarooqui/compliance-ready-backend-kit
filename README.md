# compliance-ready-backend-kit

**The audit-ready NestJS baseline: Postgres-enforced tenant isolation, RBAC, and typed
config, each wired to the compliance control your auditor will ask about.**

Most NestJS starters give you a feature list. This one gives you a **controls list**:
every capability maps to a named control in HIPAA (45 CFR Part 164), PCI-DSS v4.0.1, or
the AICPA Trust Services Criteria. The mapping lives in
[COMPLIANCE.md](./COMPLIANCE.md) and is fact-checked against the primary sources.

> ### Read this before you rely on it
>
> This kit is **technical scaffolding that supports controls**. It does not make you
> compliant and it is not a certification. HIPAA, PCI-DSS, and SOC 2 each also require
> organisational policies, workforce controls, risk assessments, and formal third-party
> assessment (a QSA or SAQ for PCI, a licensed CPA firm for a SOC 2 report). Deploying
> this repository satisfies none of those on its own.
>
> It is also **v0.1**: young, unaudited by anyone but its author, and carrying the known
> gaps listed under [Status](#status). Read that section before putting it near real data.

## Why database-per-tenant

The isolation boundary is a **separate Postgres database per tenant**, not a `tenant_id`
column and not row-level security.

A shared table with a `WHERE tenant_id = ?` predicate is one forgotten clause away from a
cross-tenant disclosure, and "we always remember the clause" is not a control an assessor
can test. With a database per tenant, the connection a request holds can only reach one
tenant's data. Postgres enforces it, so a missing predicate returns *less* data instead of
someone else's.

That is a real trade-off, not a free win. Per-tenant databases cost you connection
overhead (each live tenant holds its own pool), migrations that must be applied N times,
and cross-tenant analytics that no longer fall out of a single query. In return you get an
isolation story you can demonstrate in one `\l` and a blast radius of exactly one customer.
For regulated workloads that is usually the right trade. For a free-tier consumer product
with a million tenants, it usually is not.

The layout is a **control plane plus a data plane**:

```
master database (control plane)        tenant databases (data plane)
+---------------------------+          +---------------------------+
| tenants                   |--------->| tenant_acme               |
|   id, slug, database_name |          |   users, roles,           |
|   status                  |          |   permissions,            |
| global_config             |          |   role_permissions,       |
+---------------------------+          |   user_roles              |
                                       +---------------------------+
                                       | tenant_globex             |
                                       |   (same schema, own db)   |
                                       +---------------------------+
```

`ConnectionManager` ([packages/db/src/connection-manager.ts](packages/db/src/connection-manager.ts))
owns the registry lookup, the per-tenant connection pools, and provisioning. Prisma 7
requires a driver adapter, which is what makes this clean: we construct the `pg.Pool`
ourselves and hand it to Prisma, so connection limits, lifetimes, and error handling stay
under our control and routing a request to another database is just another pool.

## Request path

Every tenant-scoped request runs the same three steps, in this order:

| # | Step | Guard | What it answers |
| --- | --- | --- | --- |
| 1 | Resolve tenant from `x-tenant-id` (id or slug) | `TenantGuard` | Which database does this request touch? |
| 2 | Decrypt + verify the token, **and** require its `tid` to be the resolved tenant | `AccessTokenGuard` | Is the caller who they say they are, and are they allowed to ask *this tenant*? |
| 3 | Caller must hold the declared permissions | `PermissionsGuard` | May they perform *this action*? |

The tenant binding in step 2 is easy to miss and does not fall out of database-per-tenant.
A validly signed token from tenant A, presented with `x-tenant-id: B`, routes correctly to
B's database (so no data crosses between tenants) yet authenticates a principal with no
account in B, carrying A's permissions. Physical isolation answers "whose data can this
connection reach". It does not answer "who is allowed to ask".

It lives in the same step as authentication, rather than in a guard of its own, so that it
cannot be omitted: any route that authenticates a token at all performs it. It also fails
closed, so an authenticated route with no `TenantGuard` in front of it breaks loudly instead
of silently skipping the check. The smoke test regression-tests both.

Because the order is load-bearing, the chain is applied as a single decorator rather than
hand-assembled guards:

```ts
@Get()
@TenantAuthenticated(PERMISSION_KEYS.usersRead)
list() {
  return this.users.list();
}
```

## Quick start

Requires Node 24 (the current LTS line, pinned in `.nvmrc`), pnpm 9, and Docker.

```bash
cp .env.example .env          # non-secret local defaults
pnpm install                  # also generates the Prisma clients
pnpm infra:up                 # Postgres + Redis (ports 55432 / 56379)
pnpm db:migrate               # apply the master schema
pnpm build
pnpm start:auth               # listens on :3011
```

Then, in another shell:

```bash
pnpm smoke                    # 68 end-to-end checks, including isolation and token forgery
```

The ports deliberately avoid 5432, 6379, 3000, and 3001. A compliance kit is usually
evaluated on a laptop that already runs another Postgres, and a port collision on first
`docker compose up` is a bad first impression. Override with `POSTGRES_PORT`, `REDIS_PORT`,
and `PORT`.

To stop the server: `pnpm stop:auth`, or `pnpm restart:auth` to do both. That kills by
**port**, not by process name, which matters more than it sounds: `nest start --watch` runs the
app as `node --enable-source-maps .../dist/main`, so a plausible-looking
`pkill -f "node dist/main.js"` matches nothing, reports success, and leaves a stale server
holding the port for the next test run to talk to.

To wipe local state and start over: `pnpm infra:reset`.

### By hand

```bash
# 1. Provision a tenant. Creates its database, applies the schema, seeds the RBAC
#    catalogue, then marks the tenant active. Creates no users.
curl -X POST localhost:3011/api/tenants -H 'content-type: application/json' \
  -d '{"slug":"acme","name":"Acme Inc"}'

# 2. Seed that tenant's first administrator. A separate, deliberate step: see below.
SEED_ADMIN_PASSWORD='correct-horse-battery' \
  pnpm db:seed:admin --tenant acme --email admin@acme.example

# 3. Log in as that administrator. Every tenant-scoped call needs x-tenant-id.
curl -X POST localhost:3011/api/auth/login \
  -H 'content-type: application/json' -H 'x-tenant-id: acme' \
  -d '{"email":"admin@acme.example","password":"correct-horse-battery"}'

# 4. Use the token.
curl localhost:3011/api/users -H 'x-tenant-id: acme' -H "authorization: Bearer $TOKEN"

# The token is encrypted, so you cannot read it in a JWT decoder. To inspect one you
# hold the keys for (this fully verifies both layers, it is not a decoder):
node scripts/decode-token.mjs "$TOKEN"
```

## The response contract

Every response follows one of exactly two shapes. Full detail, including the error catalogue
and the status code table, is in [docs/problems.md](docs/problems.md).

**Success** is always `{ success, data, meta }`. `data` is the resource itself, unwrapped, and
`meta` is always present even when empty, so a client never has to test for it. List responses
get `meta.totalCount` for free.

```json
{ "success": true,
  "data": [ { "id": "7103...", "email": "admin@acme.example" } ],
  "meta": { "totalCount": 1 } }
```

**Errors** are [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem Details, served as
`application/problem+json`:

```json
{ "type": "https://.../docs/problems.md#tenant-not-found",
  "title": "Unknown or inactive tenant",
  "status": 404,
  "detail": "Unknown or inactive tenant: acme",
  "instance": "urn:uuid:347373f6-46b7-40a1-8893-fad64151313d",
  "code": "TENANT_NOT_FOUND",
  "traceId": "347373f6-46b7-40a1-8893-fad64151313d" }
```

Both shapes carry `success`, so `body.success` is a valid check on any response. Branch on `code`, not on `type` or `title`. `title` is stable per problem type; `detail` is
specific to the occurrence. `traceId` appears in the server log for the same request, which is
the whole point of it: it is how a user's bug report gets matched to a log line.

Three things worth knowing:

- **One filter renders every error.** Before this, the API emitted three different error bodies
  depending on which layer failed, and the `error` field held a machine code in one of them and
  a human phrase in the other two. Nothing could branch on it reliably.
- **A `500` says nothing.** The cause, including any driver or SQL text, is written only to the
  server log against the `traceId`. That is a disclosure control, not tidiness.
- **`422` for invalid values, `400` for an unparseable body.** This differs from the NestJS
  default, which returns 400 for both. Keeping them apart lets a client distinguish "my
  serialiser is broken" from "my data is wrong". `422` bodies add an `errors` array locating
  each bad field with a JSON Pointer, following the illustration in RFC 9457 §3.2.

## API

| Method | Route | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/api/health` | none | Liveness. Returns service, version, `startedAt`, `uptimeSeconds` |
| `POST` | `/api/tenants` | **none (see Status)** | Provision a tenant, its database, and its RBAC catalogue. Creates no users |
| `POST` | `/api/auth/register` | tenant header only | Create an **unprivileged** user. Holds no roles until granted one |
| `POST` | `/api/auth/login` | tenant header only | Returns a nested JWT carrying `sub` (user id), `tid` (tenant id), roles, and flattened permissions |
| `GET` | `/api/users` | full chain, `users:read` | Lists users in the calling tenant's database |

All bodies follow the response contract above. Error bodies are `application/problem+json`.

### Access tokens are nested JWTs: signed, then encrypted

The claims are signed as a JWS, and that signed token is then encrypted as a JWE
(RFC 7519 §11.2 order: sign, then encrypt). Inner `HS256`; outer `A256KW` + `A256GCM` with
`cty: JWT`; two separate 256-bit keys, and config refuses to start if they are the same one.

The reason is that a signed-only JWT's payload is plaintext base64url, so anyone holding the
token, **including the browser it was issued to and the end user**, can read the tenant id,
user id, and the complete list of roles and permissions the principal holds. That is the
threat RFC 9068 §6 names. Encrypting the payload closes it.

Stated honestly, because this is easy to oversell:

- It is **not a substitute for TLS**. RFC 8725 (BCP 225) §3.2 says outright that if a JWT is
  protected end-to-end by a current transport layer, "there may be no need to apply another
  layer of cryptographic protections to the JWT".
- It does **not** mitigate token theft or replay. The result is still a bearer credential.
  RFC 9700 (BCP 240) §2.2.1 points at sender-constraining (mTLS, DPoP) for that, and the kit
  implements neither.
- It does **not** hide the size of the claim set (RFC 8725 §2.4), so token length still leaks
  roughly how many permissions a principal holds. Compressing to disguise that is forbidden
  by §3.6, so decryption rejects compressed tokens outright.

Both layers are verified on the way in, as RFC 8725 §3.3 requires. Decrypting alone would
accept a claims set forged by anyone holding the encryption key (§2.3), so the inner
signature is always checked separately. The inner `typ` is `crbk-at+jwt`, deliberately **not**
`at+jwt`: RFC 9068 §2.1 makes that value an assertion of conformance to a profile this token
does not meet (it issues no `client_id` and does not support RS256).

This is why the kit uses `jose` directly instead of `@nestjs/jwt` and `passport-jwt`:
`@nestjs/jwt` wraps `jsonwebtoken`, which is JWS-only, and `passport-jwt` reads the token
through a synchronous extractor that cannot await a decryption.

**On the inner algorithm.** HS256 is symmetric, so any party that can verify a token can also
mint one. That set currently has exactly one member, the auth service, which both issues and
verifies. It is the right choice for v0.1 and the wrong choice the moment a *second* service
needs to verify tokens it did not issue, because handing it the verification key would hand it
the ability to forge `roles` and `permissions` for any tenant. That is the trigger to move the
inner layer to ES256 or EdDSA, keep the private key in the auth service, and publish the public
key via JWKS. It is called out in the code and on the roadmap rather than left implicit.

### Why the first administrator comes from a seed file

`POST /auth/register` is unauthenticated, so the common "first user to register becomes the
admin" shortcut would hand administrative access to whoever learns a tenant slug before its
real owner signs up.

Instead, provisioning creates no users at all, and the first administrator is granted by an
explicit seed step:

```bash
SEED_ADMIN_PASSWORD='...' pnpm db:seed:admin --tenant acme --email admin@acme.example
```

Creating infrastructure and granting a human administrative access are separate decisions,
usually taken by different people at different times, and an access review wants to see them
as separate events. Keeping it out of the HTTP layer also keeps credentials out of a request
body. The script is idempotent, so it doubles as the repair path for a tenant that has lost
its administrator.

## Layout

```
packages/
  common/    domain types, the permission catalogue, domain errors
  config/    zod-validated typed config, fails fast at boot
  crypto/    Argon2id password hashing + nested-JWT issue/verify. No framework deps
  db/        Prisma schemas (master + tenant), generated clients, ConnectionManager,
             tenant admin seed script
services/
  auth/      NestJS + Fastify: tenancy, auth, RBAC, control-plane provisioning
scripts/
  smoke-test.sh
  decode-token.mjs
docs/
  problems.md    error catalogue + status codes; RFC 9457 `type` URIs resolve here
```

`packages/crypto` exists so that the two things which must never disagree cannot: the
Argon2id parameters and the token format are each defined once, and both the auth service
and the tenant admin seed script import them from there. Two copies of a work factor
eventually become two different work factors.

The permission catalogue is declared once, in
[packages/common/src/index.ts](packages/common/src/index.ts). The keys seeded into a new
tenant database and the keys checked by `@TenantAuthenticated` come from the same
constant, and the decorator is typed to `PermissionKey`. A permission that is checked but
never seeded is a permanent 403; one that is seeded but never checked is a control nobody
enforces. Both are exactly what an access review is supposed to catch, so the type system
catches them first.

### Two schemas, two clients

`packages/db/prisma/master/schema.prisma` is migrated normally. The tenant schema is
never migrated against one fixed database, because every tenant has its own, so it is
rendered to SQL and applied at provisioning time:

```bash
pnpm db:tenant-ddl    # regenerates packages/db/sql/tenant-schema.sql from the schema
```

That generated SQL is committed on purpose. It is what runs against every new tenant
database, and it is the artefact a reviewer reads to see what a tenant database contains.
Regenerate it whenever you change the tenant schema.

Applying the schema and seeding the RBAC catalogue happen in a **single transaction**.
Postgres makes DDL transactional, so a tenant database is never left with tables but no
roles. `CREATE DATABASE` cannot join a transaction, so provisioning uses the `status` column
as its completion marker: a tenant stays `provisioning`, and therefore cannot be resolved for
a request, until its database is fully built.

## Status

v0.1 is **auth + RBAC on the database-per-tenant foundation**. It builds, typechecks, and
passes a 68-check end-to-end smoke test against a live Postgres, run in CI on every push.
Known gaps, stated plainly because a compliance kit that hides its gaps is worse than no kit:

- **`POST /api/tenants` is unauthenticated.** It creates databases, which makes it the most
  privileged route here. It exists in this state for local bootstrap. Gate it behind an admin
  credential and audit logging before exposing it anywhere. This is the single biggest thing
  to fix before real use.
- **No audit log yet.** Provisioning, login, and permission changes are the events an
  assessor will ask to see, and today they are not recorded. Append-only logging is the
  next milestone.
- **No rate limiting.** Nothing throttles `/auth/login`, so nothing satisfies PCI-DSS
  8.3.4 or resists credential stuffing.
- **Permissions are baked into the access token** at login. A permission revoked
  mid-session stays usable until the token expires (default 15 minutes). If your access
  review requires immediate revocation, check against the database per request.
- **The per-tenant pool cache is unbounded.** Every tenant resolved since boot keeps its
  pool. Fine for tens of tenants, not for thousands. Evicting safely needs refcounting,
  because closing a pool while a request holds a client from it breaks that request, so
  it is deliberately left undone rather than done subtly wrong.
- **No unit test suite** beyond the end-to-end smoke test. CI runs build, typecheck, a
  tenant-DDL drift check, and the smoke test against a real Postgres, but there are no
  focused unit tests around the token codec or the connection manager yet.
- **Access tokens are not sender-constrained.** They are encrypted, but still bearer
  credentials: a stolen token is usable by whoever holds it until it expires. mTLS
  (RFC 8705) or DPoP (RFC 9449) is the actual control, and neither is implemented.
- **No key rotation.** The signing and encryption keys are single values with no `kid` and no
  overlap window, so rotating them invalidates every live token at once.
- **The inner signature is symmetric (HS256).** Fine while one service both issues and verifies
  tokens, which is the case today. A second verifying service would need the same key and could
  therefore mint tokens, so that is the point to switch to ES256/EdDSA plus JWKS. See the token
  section above.
- **TLS terminates upstream.** The kit speaks plain HTTP and assumes a load balancer or
  service mesh in front. Encryption in transit is a real control (HIPAA 164.312(e)(1),
  PCI Req 4) and it is not satisfied inside this repository.

### Roadmap

| Milestone | Contents |
| --- | --- |
| v0.2 | Authenticated + audited control plane, append-only hash-chained audit log, Redis rate limiting |
| v0.3 | Passkeys / WebAuthn, OIDC, TOTP |
| v0.4 | KMS envelope encryption for field-level secrets, key rotation |
| v0.5 | OpenTelemetry traces and metrics, structured request logging |
| Ongoing | CI security gates (CodeQL, osv-scanner, gitleaks, SBOM), per-tenant migration runner, test suite |

## Stack

NestJS 10 (Fastify adapter), TypeScript strict, Prisma 7 with the `@prisma/adapter-pg`
driver adapter, Postgres 16, Redis 7, Argon2id, pnpm workspaces.

Argon2id parameters are declared explicitly rather than left to library defaults, in one
file ([password.service.ts](services/auth/src/auth/password.service.ts)), so that "what
key-derivation function, at what work factor" has a single readable answer that a library
upgrade cannot silently change.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). To report a vulnerability, see
[SECURITY.md](./SECURITY.md) rather than opening a public issue.

This repository is **clean-room**: every line is written from public specifications and
standards. No code is copied or adapted from any employer or client. Contributions are
accepted on the same terms.

## Licence

[MIT](./LICENSE). Written by [Faiz Ahmed Farooqui](https://faizahmed.in).
