# compliance-ready-backend-kit

**A NestJS + Postgres baseline built as a controls list, not a feature list: Postgres-enforced
tenant isolation, RBAC, and encrypted access tokens, each mapped to the named HIPAA / PCI-DSS /
SOC 2 control an assessor will ask about, and each marked implemented or not.**

Most NestJS starters give you a feature list. This one gives you a **controls list**: every
capability maps to a named control in HIPAA (45 CFR Part 164), PCI-DSS v4.0.1, or the AICPA
Trust Services Criteria, fact-checked against the primary sources.

**And it tells you which of them actually exist.** The mapping in
[COMPLIANCE.md](./COMPLIANCE.md) carries a Status column: five controls are implemented, three are
partial, and five are not built yet. A control mapping without that column is a marketing
document, because the reader cannot tell a shipped control from an intention. Audit logging is
currently in the "not built yet" list, which is why this page no longer describes the kit as
audit-ready.

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
pnpm smoke                    # 66 end-to-end checks, including isolation and token forgery
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
| `POST` | `/api/tenants` | **control-plane key** | Provision a tenant, its database, and its RBAC catalogue. Creates no users. 30/hour |
| `POST` | `/api/auth/register` | tenant header only | Create an **unprivileged** user. Holds no roles until granted one. 10/min |
| `POST` | `/api/auth/login` | tenant header only | Returns a nested JWT carrying `sub` (user id), `tid` (tenant id), roles, and flattened permissions. 20/min, plus failure throttling |
| `GET` | `/api/users` | full chain, `users:read` | Lists users in the calling tenant's database |
| `GET` | `/.well-known/jwks.json` | none | Public verification keys. A bare JWK Set, deliberately not enveloped |
| `GET` | `/docs` | none | OpenAPI UI. Document at `/docs/openapi.json` and `/docs/openapi.yaml` |

All bodies follow the response contract above, except `/.well-known/jwks.json`. Error bodies are
`application/problem+json`.

### Browsable docs, and why the spec is not generated naively

`/docs` serves the OpenAPI UI; `/docs/openapi.json` and `/docs/openapi.yaml` serve the document.
`API_DOCS_ENABLED=false` turns all of it off, and the service logs a warning if it is left on with
`NODE_ENV=production`, because an OpenAPI document is a complete map of every route, parameter and
constraint. That is its value to an integrator and equally its value to an attacker.

One thing had to be built rather than generated. Handlers return a bare resource and an interceptor
wraps it in `{ success, data, meta }`, and the OpenAPI generator reads return types without knowing
interceptors exist. Left alone it documents the resource at the top level, which is not a cosmetic
inaccuracy: a generated client compiles, runs, and deserialises every field to `undefined`. So every
success response is declared through an `ApiEnvelope` helper that composes the envelope with the
concrete resource via `allOf`, and the smoke test fails if any 2xx response in the published document
is missing that composition.

### Rate limiting and login throttling

Two controls, both on Redis, using a sliding window evaluated atomically in a Lua script. A fixed
window would have been shorter to write and would permit twice the limit across a boundary, which for a
request budget is untidy and for login throttling is the whole control.

**Request budgets** apply per client: 100/min by default, with stricter budgets where the work is
expensive or privileged (`/auth/login` 20/min, `/auth/register` 10/min, `POST /tenants` 30/hour). A
route with its own budget is checked against *both*, because a stricter limit is asking for less than
the default, not for a fresh allowance on top of it. Every response carries `X-RateLimit-Limit` and
`X-RateLimit-Remaining`; a 429 adds `Retry-After` in whole seconds and `Cache-Control: no-store`.

**Login throttling** counts *failed* logins per account and per source address. Two axes, because one
address against many accounts and many addresses against one account are different attacks and each
counter only sees one of them. A successful login clears the account counter but **not** the address
counter: clearing both would hand anyone holding a single valid account a reset button for their own
address budget. Failures are counted rather than attempts, so a user who mistypes and then succeeds is
never nearer a limit.

Two settings deserve a decision rather than a default:

- **`TRUST_PROXY`** decides what `request.ip` means, and therefore whether rate limiting works at all.
  Left `false` behind a load balancer, every request appears to come from the balancer and all traffic
  shares one bucket, so the first busy client throttles everyone. Set `true` without a trusted proxy in
  front, and any caller sends `X-Forwarded-For` to get a fresh bucket per request. It defaults to
  `false` because that failure is loud and the other is silent.
- **`RATE_LIMIT_FAIL_OPEN`** decides what happens when Redis is unreachable. Open by default, because
  closed turns a Redis blip into a total API outage including login, which is a bigger incident than
  the one being prevented. Every occurrence is logged at error level and the response carries
  `X-RateLimit-Degraded: true`, so the degradation is visible rather than quiet.

### The control plane needs its own credential

`POST /api/tenants` creates a database, which made it the most privileged route in the kit, and until
v0.2 it was unauthenticated behind a source comment asking people not to expose it. That is not a
control: nothing enforced it and nothing detected the mistake.

It now requires `Authorization: Bearer $CONTROL_PLANE_API_KEY`. The key is **required** with no
default, so the service refuses to boot without one rather than silently reopening the hole. A user
access token deliberately cannot be used instead: at the moment of the call there is no tenant to be a
member of and no user to hold a role, so every data-plane credential is scoped to something that does
not exist yet.

The honest limitation, which matters for an access review: a shared secret authenticates the **bearer**,
not a person. It cannot say which operator provisioned a tenant, cannot be scoped to one action, and
rotating it invalidates every caller at once. Enough to close the hole; not enough for attributable
administrative access, which needs mutual TLS or a signed operator token carrying an identity.

### Request-level DoS limits, and a Fastify option that silently does nothing

`requestTimeout`, `connectionTimeout`, `keepAliveTimeout` and `bodyLimit` are declared explicitly in
validated config rather than inherited, for the same reason the Argon2id parameters are: a value that
governs a security property should have one readable answer that a library upgrade cannot change
quietly.

The request timeout is worth its own note, because setting it the obvious way does not work.
**Fastify's `requestTimeout` option has no effect for any value under 60 seconds, and fails silently.**
Node derives `headersTimeout = min(60000, requestTimeout)` inside `http.createServer` and validates
`headersTimeout <= requestTimeout` there and only there. Fastify creates the server first and assigns
`server.requestTimeout` afterwards without touching `headersTimeout`, so a configured 30s leaves an
inconsistent pair that the constructor would have rejected, and Node's expiry sweep then never expires
anything. Fastify's own default of `0` is worse than it looks: it is assigned unconditionally, so it
does not inherit Node's 300s, it *disables* the timeout.

The kit therefore passes the value through `http` (the constructor) **and** at the top level. Verified
against a real socket rather than by reading: `pnpm smoke:slowloris` completes valid headers, declares a
`Content-Length`, dribbles the body one byte at a time, and asserts the server answers `408` and hangs
up. Every other combination leaves the body unbounded.

### Access tokens are nested JWTs: signed, then encrypted

The claims are signed as a JWS, and that signed token is then encrypted as a JWE
(RFC 7519 §11.2 order: sign, then encrypt). Inner **`ES256`**; outer `A256KW` + `A256GCM` with
`cty: JWT`. Both layers name their key with a `kid`, and the keys live in a registry rather than in
configuration.

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

**Why ES256 and not HS256.** HS256 is symmetric, so anything able to verify a token is also able to
mint one. That is tolerable while a single service does both, and wrong the moment a second service
verifies tokens it did not issue, because handing it the verification key hands it the power to forge
`roles` and `permissions` for any tenant. With ES256 a verifier receives only the public half.
RFC 7518 §3.1 rates ES256 `Recommended+`, above RS256's `Recommended`.

The public keys are published at **`/.well-known/jwks.json`**, at the origin root rather than under
`/api`, because RFC 8615 reserves `/.well-known/`. The document is a plain JWK Set (RFC 7517 §5)
served as `application/jwk-set+json`, deliberately **not** wrapped in the success envelope, so
standard clients such as jose's `createRemoteJWKSet` consume it directly. Every entry carries `kid`,
`alg` and `use`, so a verifier can select a key with no out-of-band knowledge.

**What the JWKS does not buy you, stated plainly.** The public half is enough to check the inner
signature, but it is not enough to read a token, because the outer JWE is **symmetric** (`A256KW`).
A second service cannot verify a kit-issued token from the JWKS alone: it has to be given the
active encryption key as well, and that key lets it decrypt every token it sees. What it still
cannot do is **mint** one, because signing needs the ES256 private key that never leaves the
registry. So the honest summary is that ES256 splits minting from verifying, which is the property
that matters, while the encryption layer remains a shared secret between services that are trusted
to read claims. Publishing an asymmetric outer layer (`ECDH-ES`) would close that too and is not
implemented.

### Keys live in a registry, not in configuration

`config_keys` in the master database holds them, **wrapped**, never in plaintext. The only key left
in configuration is the key-encrypting key that wraps the others. A key in config is a key in every
deploy manifest, CI secret store and developer shell; one KEK can move into KMS, an HSM or an enclave
without touching anything else, which is what the `KeyProvider` port exists for.

```bash
pnpm keys:init                       # create the first key of each purpose
pnpm keys:rotate                     # new key active, previous one retiring
pnpm keys:list                       # show the registry
pnpm keys:revoke --kid K --reason R  # destroy the material, keep the row as evidence
pnpm keys:decode "$TOKEN"            # verify a token and print its claims
```

Rotation is graceful. Activating a new key moves the previous one to `retiring`, where it still
**verifies** for the access-token TTL plus the clock tolerance, so tokens issued a moment before a
rotation keep working instead of every live session breaking. Running instances pick up a rotation
within a minute without a restart. The lifecycle is enforced by Postgres, not by application code: a
partial unique index permits only one `active` key per purpose, and CHECK constraints pair purpose to
algorithm, require a public JWK for asymmetric keys, and refuse a `revoked` row that still holds key
material.

Keys are **deployment-wide, not per tenant**. Which tenant a token belongs to is the `tid` claim
inside the ciphertext, so a per-tenant key would force a verifier to learn the tenant before it could
verify anything, and every way of doing that is broken: from the claim is circular, from the outer
header leaks the tenant on every token, and from the `x-tenant-id` header makes key selection
attacker-directed. The honest cost is that database-per-tenant isolates data but not this credential:
compromise the active signing key and you can forge tokens for any tenant.

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

v0.2 is **auth + RBAC + a key registry + rate limiting + an authenticated control plane**, on the
database-per-tenant foundation. It builds, typechecks, passes 192 unit tests and an 88-check
end-to-end smoke test against a live Postgres and Redis, run in CI on every push.

Known gaps, stated plainly because a compliance kit that hides its gaps is worse than no kit:

- **No audit log yet.** Provisioning, login, and permission changes are the events an
  assessor will ask to see, and today they are not recorded. This is the single biggest
  remaining gap and the rest of v0.2. Note what it means for the control plane: the credential
  authenticates the bearer rather than a person, so even once events are recorded, "which operator
  provisioned this tenant" will need mutual TLS or a signed operator token to answer.
- **Login throttling is not a substitute for MFA.** It resists credential stuffing against an
  account or from an address, and it does nothing about one attempt per account across ten thousand
  accounts, which trips no per-account counter. Phishing-resistant MFA is the actual control and it
  is not implemented.
- **Rate limiting bounds requests, not bandwidth.** It runs in the application, so the traffic has
  already arrived. Anything volumetric belongs at the load balancer or a CDN.
- **Permissions are baked into the access token** at login. A permission revoked
  mid-session stays usable until the token expires (default 15 minutes). If your access
  review requires immediate revocation, check against the database per request.
- **The per-tenant pool cache is unbounded.** Every tenant resolved since boot keeps its
  pool. Fine for tens of tenants, not for thousands. Evicting safely needs refcounting,
  because closing a pool while a request holds a client from it breaks that request, so
  it is deliberately left undone rather than done subtly wrong.
- **The layers that talk to Postgres have no unit tests.** The token codec, the key
  provider, the key registry, config validation and the RBAC guard are unit tested; the
  connection manager, the services and the operator CLIs are not. Their behaviour depends
  on real database semantics (transactional DDL, unique-violation codes, partial indexes)
  that a mock would only assert assumptions about, so they are covered end to end by
  `scripts/smoke-test.sh` against a real cluster instead. Overall line coverage is
  around 50%, and `vitest.config.ts` records where the real gates are.
- **Access tokens are not sender-constrained.** They are encrypted, but still bearer
  credentials: a stolen token is usable by whoever holds it until it expires. mTLS
  (RFC 8705) or DPoP (RFC 9449) is the actual control, and neither is implemented.
- **The key-encrypting key is in configuration.** Envelope encryption, rotation and a JWKS are all
  implemented, but no KMS or HSM adapter is written yet, so the KEK is only as protected as the
  process and its config store. The `KeyProvider` port is the seam for fixing that.
- **TLS terminates upstream.** The kit speaks plain HTTP and assumes a load balancer or
  service mesh in front. Encryption in transit is a real control (HIPAA 164.312(e)(1),
  PCI Req 4) and it is not satisfied inside this repository.

### Roadmap

| Milestone | Contents |
| --- | --- |
| v0.2 | **Landed:** authenticated control plane, Redis rate limiting + login throttling, request-level DoS limits. **Remaining:** append-only hash-chained audit log, which is what makes the control plane *audited* as well as authenticated |
| v0.3 | Passkeys / WebAuthn, OIDC, TOTP |
| v0.4 | KMS and HSM `KeyProvider` adapters, field-level envelope encryption |
| v0.5 | OpenTelemetry traces and metrics, structured request logging |
| Ongoing | CI security gates (CodeQL, osv-scanner, gitleaks, SBOM), per-tenant migration runner, test suite |

## Stack

NestJS 11 (Fastify adapter), TypeScript strict, Prisma 7 with the `@prisma/adapter-pg`
driver adapter, Postgres 16, Redis 7, Argon2id, pnpm workspaces.

Argon2id parameters are declared explicitly rather than left to library defaults, in one
file ([packages/crypto/src/passwords.ts](packages/crypto/src/passwords.ts)), so that "what
key-derivation function, at what work factor" has a single readable answer that a library
upgrade cannot silently change. Everything cryptographic lives in that package for the same
reason: two copies of a work factor or a token format eventually disagree.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). To report a vulnerability, see
[SECURITY.md](./SECURITY.md) rather than opening a public issue.

This repository is **clean-room**: every line is written from public specifications and
standards. No code is copied or adapted from any employer or client. Contributions are
accepted on the same terms.

## Licence

[MIT](./LICENSE). Written by [Faiz Ahmed Farooqui](https://faizahmed.in).
