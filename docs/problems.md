# Error catalogue

Every error this API returns is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem
Details document, served as `application/problem+json`. The `type` member of each response is a
link into this page, which is why the anchors below matter: they are part of the API contract,
so do not rename one without treating it as a breaking change.

## The shape

```json
{
  "success": false,
  "type": "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/docs/problems.md#tenant-not-found",
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

### `route-not-found`

`ROUTE_NOT_FOUND` · **404**

No route matches that method and path.

### `too-many-requests`

`TOO_MANY_REQUESTS` · **429**

Reserved, and **not yet emitted**: rate limiting is not implemented (see COMPLIANCE.md). The code
and title exist in the filter so that the contract is settled before the control lands, and this
section exists so the `type` URI is not a link to a heading that does not exist. The smoke test
asserts every emitted code has a section here, which is why a reserved code needs one too.

When it does land, the response will carry a `Retry-After` header. Two details worth stating now,
because both are easy to get wrong: RFC 6585 §4 makes `Retry-After` on a 429 a **MAY** rather than
a requirement, and RFC 9110 §10.2.3 defines `delay-seconds` as a non-negative **integer**, so a
fractional or negative value is malformed. Responses with 429 also MUST NOT be cached.

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
