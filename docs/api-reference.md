# API reference

Every route, what guards it, and worked examples. Shapes below were captured from a running service.

Base path is `/api`, except `/.well-known/jwks.json` which is served at the origin root.

A browsable OpenAPI document is at `/docs` when `API_DOCS_ENABLED` is true (the default). Turn it off in
production unless you mean to publish a complete map of every route and constraint.

## Route summary

| Method | Path | Auth | Rate limit |
| --- | --- | --- | --- |
| `GET` | `/api/health` | none | exempt |
| `POST` | `/api/tenants` | control-plane credential | 30/hour |
| `POST` | `/api/auth/register` | tenant header only | 10/min |
| `POST` | `/api/auth/login` | tenant header only | 20/min |
| `GET` | `/api/users` | token + `users:read` | 100/min |
| `GET` | `/.well-known/jwks.json` | none | 100/min |

Every tenant-scoped route requires the `x-tenant-id` header, carrying the tenant slug or uuid.

## `GET /api/health`

Liveness. **Deliberately does not touch the database**: a liveness probe that fails on a Postgres blip
gets the container killed during an incident, which is the opposite of helpful. A dependency-checking
readiness probe is roadmap.

```bash
curl localhost:3011/api/health
```

```json
{
  "success": true,
  "data": {
    "status": "ok",
    "service": "@compliance-kit/auth-service",
    "version": "0.1.0",
    "startedAt": "2026-07-31T19:20:41.489Z",
    "uptimeSeconds": 0
  },
  "meta": {}
}
```

`uptimeSeconds` is the field to check when test results look impossible: a large number means you are
talking to a stale server. See
[getting started](getting-started.md#if-results-look-impossible-check-which-server-you-are-talking-to).

## `POST /api/tenants`

Provisions a tenant: creates its database, applies the schema and the audit-log triggers, seeds the RBAC
catalogue and the `tenant-admin` role, then marks it active. **Creates no users.**

Requires the control-plane credential. This route creates databases.

```bash
curl -X POST localhost:3011/api/tenants \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $CONTROL_PLANE_API_KEY" \
  -d '{"slug":"acme","name":"Acme Corporation"}'
```

| Field | Rules |
| --- | --- |
| `slug` | matches `^[a-z][a-z0-9-]{1,40}$`. Lowercase, starts with a letter, hyphens allowed |
| `name` | string, minimum 2 characters |

The slug pattern is strict because the slug reaches an identifier position in DDL: it becomes the database
name as `tenant_<slug>`. It is validated again downstream rather than trusted once.

Responses: `201` on success, `401 CONTROL_PLANE_UNAUTHORIZED` without a valid credential,
`409 TENANT_ALREADY_EXISTS` on a duplicate slug, `422 VALIDATION_FAILED` on a bad slug or name.

Emits `tenant.provisioned` to the master audit chain, with actor type `control_plane` and no actor id.
See [audit log](audit-log.md#what-the-control-plane-chain-cannot-tell-you).

## `POST /api/auth/register`

Creates an unprivileged user in the named tenant. **Unauthenticated**, which is why the first
administrator comes from a seed file instead: see
[multi-tenancy](multi-tenancy.md#why-the-first-administrator-comes-from-a-seed-file).

A registered user holds **no roles**, so they can authenticate and can do nothing until granted a role.

```bash
curl -X POST localhost:3011/api/auth/register \
  -H 'content-type: application/json' -H 'x-tenant-id: acme' \
  -d '{"email":"user@acme.example","password":"correct-horse-battery-staple"}'
```

| Field | Rules |
| --- | --- |
| `email` | valid email; normalised before storage |
| `password` | string, minimum 12 characters |

**Length is the only password rule.** No maximum length and no character-class requirements, deliberately:
Argon2id hashes any input to a fixed size, so a cap buys nothing, and composition rules push people
towards predictable substitutions.

```json
{ "success": true, "data": { "id": "…uuid…", "email": "user@acme.example" }, "meta": {} }
```

Responses: `201`, `409 EMAIL_ALREADY_REGISTERED`, `422 VALIDATION_FAILED`, `404 TENANT_NOT_FOUND`,
`429 TOO_MANY_REQUESTS`.

Emits a registration event with actor type `system`, not `user`: the account did not exist when the
request arrived, so nobody was authenticated, and recording the new user as its own actor would imply it
authorised its own creation.

## `POST /api/auth/login`

```bash
curl -X POST localhost:3011/api/auth/login \
  -H 'content-type: application/json' -H 'x-tenant-id: acme' \
  -d '{"email":"admin@acme.example","password":"correct-horse-battery-staple"}'
```

```json
{ "success": true, "data": { "accessToken": "eyJhbGciOiJBMjU2S1ciLCJl…" }, "meta": {} }
```

**The body carries only the token.** Its lifetime is `JWT_ACCESS_TTL_SECONDS` (900 default) and travels as
the `exp` claim inside the token rather than as a separate field.

That token prefix is not decorative: `eyJhbGciOiJBMjU2S1ci` decodes to `{"alg":"A256KW"`, the **outer JWE**
header. There is no readable payload, because the claims are encrypted. Inspect one with
`pnpm keys:decode <token>`, which fully verifies both layers first.

Responses: `200`, `401 INVALID_CREDENTIALS`, `429 TOO_MANY_REQUESTS`, `404 TENANT_NOT_FOUND`,
`422 VALIDATION_FAILED`.

**A wrong password and an unknown email are indistinguishable**, in both body and timing. An unknown email
still verifies the supplied password against a decoy hash so the two paths take the same time; otherwise
latency enumerates valid accounts. A smoke assertion checks both return the identical shape.

Two separate limits apply. The request rate limit (20/min per client), and login throttling on **failures**
per account and per source address (10 per 15 minutes), which clears on success. Exceeding either returns
429. See [rate limiting](rate-limiting.md#login-throttling-is-a-different-control).

## `GET /api/users`

Lists users in the tenant. Requires a valid token **and** the `users:read` permission.

```bash
curl localhost:3011/api/users \
  -H 'x-tenant-id: acme' -H "authorization: Bearer $TOKEN"
```

```json
{
  "success": true,
  "data": [
    { "id": "…", "email": "admin@acme.example", "status": "active", "createdAt": "2026-07-31T…" }
  ],
  "meta": { "totalCount": 1 }
}
```

`meta.totalCount` is added automatically for array payloads.

Responses: `200`, `401 INVALID_ACCESS_TOKEN`, `401 CROSS_TENANT_TOKEN`, `403` when the permission is
missing, `400 TENANT_CONTEXT_MISSING` with no header, `404 TENANT_NOT_FOUND`.

**`CROSS_TENANT_TOKEN` is the interesting one.** A valid token for tenant A sent with `x-tenant-id: B` is
rejected, even though database-per-tenant means no data would have crossed. The caller would have been
acting inside a tenant they hold no account in, carrying A's permissions. See
[request lifecycle](request-lifecycle.md#4-accesstokenguard).

A 403 records an `authz.denied` event on the tenant's chain, capturing what was required and what was
missing. The response says only "Missing required permission".

## `GET /.well-known/jwks.json`

Public signing keys, as a JWK Set. At the **origin root**, not under `/api`, per RFC 8615.

```bash
curl localhost:3011/.well-known/jwks.json
```

```json
{ "keys": [ { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "kid": "…", "alg": "ES256", "use": "sig" } ] }
```

**No envelope.** This route is marked `@RawResponse()` because wrapping a JWK Set in `{ success, data }`
breaks every standard consumer, including `jose`'s own `createRemoteJWKSet`. Smoke assertions check the
raw wire format and that no private scalar (`d`) is present.

Publishing this does **not** let a third party verify tokens with public keys alone: the outer layer is
symmetric. See [key management](key-management.md#the-outer-layer-is-a-shared-secret).

## Errors

Every error is `application/problem+json` per RFC 9457:

```json
{
  "success": false,
  "type": "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/problems.md#tenant-not-found",
  "title": "Unknown or inactive tenant",
  "status": 404,
  "detail": "Unknown or inactive tenant: nope",
  "instance": "urn:uuid:c78a7f8d-160e-4120-ba09-aa4660fb9d85",
  "code": "TENANT_NOT_FOUND",
  "traceId": "c78a7f8d-160e-4120-ba09-aa4660fb9d85"
}
```

Branch on `code`, not on `title` or `detail`. `code` is stable; the other two are prose.

`body.success` discriminates on **any** response, success or error, which is the whole reason it appears on
both shapes.

Full catalogue with every code and status in [problems.md](../problems.md); the contract itself in
[the response contract](responses.md).

## Not implemented

No refresh tokens, no logout or token revocation (tokens expire), no user update or delete, no role
management API, no password reset, no pagination on `GET /api/users`, and no MFA enrolment. `roles:manage`
exists as a permission with no route behind it yet.
