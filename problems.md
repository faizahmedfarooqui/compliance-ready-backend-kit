# Error catalogue

Every error this API returns is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem
Details document, served as `application/problem+json`. The `type` member of each response is a
link into this page, which is why the anchors below matter: they are part of the API contract,
so do not rename one without treating it as a breaking change.

## The shape

```json
{
  "success": false,
  "type": "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/problems.md#tenant-not-found",
  "title": "Unknown or inactive tenant",
  "status": 404,
  "detail": "Unknown or inactive tenant: acme",
  "instance": "urn:uuid:347373f6-46b7-40a1-8893-fad64151313d",
  "code": "TENANT_NOT_FOUND",
  "traceId": "347373f6-46b7-40a1-8893-fad64151313d"
}
```

| Member | Source | Notes |
| --- | --- | --- |
| `success` | §3.2 extension | Always `false`. Mirrors the success envelope's `success: true`, so `body.success` discriminates on **any** response. Carried on only one of the two shapes it would always be `true`, and would tell a client nothing. |
| `type` | RFC 9457 §3.1.1 | Identifies the problem **type**. Branch on `code` instead; this is for humans and tooling. |
| `title` | §3.1.3 | Stable per type. Never contains request data. |
| `status` | §3.1.2 | Advisory copy of the HTTP status. The real status line always matches. |
| `detail` | §3.1.4 | Specific to this one occurrence, so it may contain a slug or field name. |
| `instance` | §3.1.5 | `urn:uuid:` identifying this occurrence. Not dereferenceable, which §3.1.5 permits. |
| `code` | §3.2 extension | **The member to branch on.** Stable, machine-readable. |
| `traceId` | §3.2 extension | Same uuid as `instance`, unwrapped. Quote it in a bug report; it is in the server logs. |
| `errors` | §3.2 extension | Validation failures only. See below. |

**Clients must ignore unrecognised members** (§3.2), so new extensions can be added without a
breaking change.

## Validation failures

`422` responses add an `errors` array, matching the illustration in RFC 9457 §3.2. Each entry
locates the offending field with a [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901):

```json
{
  "success": false,
  "type": ".../problems.md#validation-failed",
  "title": "Request validation failed",
  "status": 422,
  "detail": "One or more fields are invalid",
  "code": "VALIDATION_FAILED",
  "errors": [
    { "detail": "property extra should not exist", "pointer": "#/extra" },
    { "detail": "slug must be lowercase, start with a letter, and use only a-z, 0-9, hyphen", "pointer": "#/slug" }
  ]
}
```

### Why 422 and not 400

They mean different things here, and the distinction is useful:

- **400 `MALFORMED_REQUEST`** — the body could not be parsed at all. Fastify rejects it before
  any validation runs.
- **422 `VALIDATION_FAILED`** — the body parsed fine, but values were unacceptable.

So a client can tell "my serialiser is broken" from "my data is wrong" without reading prose.
Note this differs from the NestJS default, which returns 400 for both.

## Status codes

| Status | When |
| --- | --- |
| `200` | Request succeeded. |
| `201` | Resource created (`POST /api/tenants`, `POST /api/auth/register`). |
| `400` | Body is unparseable, or a tenant context was required and missing. |
| `401` | Not authenticated: bad credentials, or a missing, invalid, expired, or wrong-tenant token. |
| `403` | Authenticated, but lacking a required permission. |
| `404` | Unknown tenant, or no such route. |
| `409` | Conflict with existing state: duplicate tenant slug or email. |
| `422` | Body parsed but failed validation. |
| `500` | Unexpected server fault. Body carries a `traceId` and nothing else. |

## Catalogue

### `tenant-not-found`

`TENANT_NOT_FOUND` · **404**

The `x-tenant-id` header named a tenant that does not exist, or one that is not `active`. A
tenant is not active while it is still being provisioned, or after it has been suspended.

Note this is deliberately the same response for "no such tenant" and "suspended tenant": which
one it is would tell an unauthenticated caller whether a given slug is taken.

### `tenant-context-missing`

`TENANT_CONTEXT_MISSING` · **400**

The route is tenant-scoped but no tenant was resolved. Almost always a missing `x-tenant-id`
header. Every route except `POST /api/tenants` needs one.

### `tenant-already-exists`

`TENANT_ALREADY_EXISTS` · **409**

A tenant with that slug is already registered. Slugs are unique across the deployment and
become part of the tenant's database name, so they cannot be reused.

### `validation-failed`

`VALIDATION_FAILED` · **422**

One or more body fields were rejected. See the `errors` array for per-field detail. Note that
unknown properties are rejected rather than ignored, so a typo in a field name is an error, not
a silent no-op.

### `malformed-request`

`MALFORMED_REQUEST` · **400**

The request body could not be parsed, typically invalid JSON with a JSON content type.

### `email-already-registered`

`EMAIL_ALREADY_REGISTERED` · **409**

That email address already has an account **in this tenant**. Addresses are unique per tenant,
not globally, and are compared case-insensitively: `Alice@example.com` and `alice@example.com`
are the same account.

### `invalid-credentials`

`INVALID_CREDENTIALS` · **401**

Login failed. Returned identically whether the address is unregistered or the password is
wrong, and the two paths spend comparable CPU, so neither the body nor the response time
reveals which addresses exist.

### `invalid-access-token`

`INVALID_ACCESS_TOKEN` · **401**

The `Authorization: Bearer` token was missing, malformed, expired, not encrypted, or failed
either layer of verification. One code covers all of them on purpose: reporting which check
failed would tell an attacker which part of a forged token to fix next.

### `cross-tenant-token`

`CROSS_TENANT_TOKEN` · **401**

The token is valid, but its `tid` claim names a different tenant than the `x-tenant-id` header.
Database-per-tenant would have routed the query to the right database, so no data would have
crossed; this rejects the caller acting inside a tenant they hold no account in. See the token
section of the README.

### `forbidden`

`FORBIDDEN` · **403**

The caller is authenticated, and is not allowed to do this. Raised by the RBAC guard when the token
carries no `permissions` entry matching what the route requires.

**403, not 404.** Hiding the existence of a route the caller cannot use would be defensible for a
resource whose existence is itself sensitive; here the routes are published in the OpenAPI document, so
a 404 would only make a legitimate integrator's permission problem harder to diagnose.

**Permissions come from the token, not from a live lookup.** They are baked in when the token is
signed, so a permission revoked mid-session remains usable until the token expires (15 minutes by
default). That is the standard trade for stateless tokens, and if your access review requires immediate
revocation you need a per-request check or a revocation list.

Until v0.2 this response carried `code: "HTTP_403"` and a `type` URI pointing at `#http-403`, a heading
that has never existed, so the one promise RFC 9457 makes about `type` was broken for the most common
authorization failure in the kit. The smoke test now asserts that every code the OpenAPI document
mentions has a section here, which is what surfaced it.

### `route-not-found`

`ROUTE_NOT_FOUND` · **404**

No route matches that method and path.

### `control-plane-unauthorized`

`CONTROL_PLANE_UNAUTHORIZED` · **401**

A control-plane route was called without a valid credential. Present it as
`Authorization: Bearer <CONTROL_PLANE_API_KEY>`.

Today the only such route is `POST /api/tenants`, which creates a database. It was unauthenticated
until v0.2, guarded by nothing but a source comment asking people not to expose it.

**One error for every cause.** A missing header, a wrong key, and a key sent without the `Bearer`
scheme all produce exactly this response. Separating them would tell someone probing the endpoint
whether it is protected at all and whether their header shape was accepted, which is two free
observations while guessing a credential.

The comparison is constant-time over the credential itself, after an explicit length check. The length
is deliberately not protected, because it is not a secret: the config schema fixes it at 43 base64url
characters and `.env.example` publishes that, so rejecting a wrong-length credential early tells a
caller only what the documentation already does. What is constant-time is the comparison of two values
of the correct length, which is where guessing the content would otherwise leak a prefix at a time.

The credential authenticates the **bearer**, not a person: it cannot say which operator called. See
`controlPlaneApiKey` in `packages/config` for why that is a documented stepping stone rather than a
finished design.

### `too-many-requests`

`TOO_MANY_REQUESTS` · **429**

A rate limit was exceeded. Emitted by two different controls, and the body deliberately does not say
which:

- **The per-client request budget**, applied to every route. `RATE_LIMIT_DEFAULT_LIMIT` per
  `RATE_LIMIT_DEFAULT_WINDOW_MS`, plus a stricter budget on routes that declare one (`/auth/login`,
  `/auth/register`, `POST /tenants`).
- **Login throttling**, which counts failed logins per account and per source address. Failures only,
  cleared on a successful login, so ordinary use never approaches it.

The response carries:

- **`Retry-After`**, in seconds. RFC 6585 §4 makes this a **MAY** rather than a requirement, and RFC
  9110 §10.2.3 defines `delay-seconds` as a non-negative **integer**, so the value is rounded up and
  floored at 1: a sub-second wait must not serialise as `0`, which would tell a client to retry at once.
- **`Cache-Control: no-store`**, because RFC 6585 §4 says a 429 "MUST NOT be stored by a cache". A
  shared cache replaying one would hand a 429 to callers who are within their limit, or keep serving it
  after the window has passed.
- **`X-RateLimit-Limit`** and **`X-RateLimit-Remaining`** on every response, not just this one. The
  `RateLimit` and `RateLimit-Policy` fields from draft-ietf-httpapi-ratelimit-headers are the better
  design, but they are still an Internet-Draft and this kit does not claim conformance to unpublished
  specifications.

`X-RateLimit-Degraded: true` appears instead when the limiter could not reach Redis. The request was
served without being counted (see `RATE_LIMIT_FAIL_OPEN`), and there is no honest limit or remaining
count to report, so neither is sent.

**Why the detail says nothing specific.** On the login route, distinguishing "this account is
throttled" from "this address is throttled" would confirm that the named account exists, which is the
same disclosure `invalid-credentials` exists to prevent.

### `internal-error`

`INTERNAL_ERROR` · **500**

An unexpected fault. The body contains a `traceId` and deliberately nothing else: the cause,
including any driver or SQL detail, is written only to the server log against that same id.
Quote the `traceId` when reporting it.

## Adding a problem type

1. Add a `DomainError` subclass in `packages/common/src/index.ts` with a stable `title`, an
   occurrence-specific message, and a `SCREAMING_SNAKE` code.
2. Map the code to a status in `STATUS_BY_ERROR` in
   `services/auth/src/common/problem-details.filter.ts`.
3. Add a section here whose anchor is the code in kebab-case, because the `type` URI is derived
   from the code and will otherwise link to a heading that does not exist.
4. Add a smoke-test assertion for it.
