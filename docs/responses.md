# Response contract

One success shape, one error shape, and the reasoning behind each field.

## The two shapes

**Success**, on every 2xx:

```json
{ "success": true, "data": { }, "meta": { } }
```

**Error**, on everything else, served as `application/problem+json` per RFC 9457:

```json
{
  "success": false,
  "type": "https://…/problems.md#tenant-not-found",
  "title": "Unknown or inactive tenant",
  "status": 404,
  "detail": "Unknown or inactive tenant: nope",
  "instance": "urn:uuid:…",
  "code": "TENANT_NOT_FOUND",
  "traceId": "…"
}
```

Both are declared in `packages/common/src/index.ts`, framework-free, so a generated SDK or a future
service imports the same definitions rather than re-describing them.

## Why there is a contract at all

Before this existed, the service shipped **three mutually inconsistent error shapes**:

| Source | Body |
| --- | --- |
| `ValidationPipe` | `{"message":["property extra should not exist"],"error":"Bad Request","statusCode":400}` |
| the old domain filter | `{"error":"TENANT_NOT_FOUND","message":"Unknown or inactive tenant: nope"}` |
| Nest's 404 fallback | `{"message":"Cannot GET /api/nonexistent","error":"Not Found","statusCode":404}` |

So `error` was a **machine code** in one and a **human phrase** in the other two, and `statusCode` appeared
in two of three. No client could branch on any of it. That is the problem the contract solves, and it is
worth stating because it is the normal state of an API that grew one handler at a time.

RFC 9457 was chosen over a custom envelope because it is standards-track, and because "we invented our own
error format" is a weaker answer than "we implement the IETF one" when someone is assessing your API.

## The success envelope

`ResponseEnvelopeInterceptor` wraps every 2xx. Handlers return bare resources:

```ts
@Get()
async list(): Promise<UserSummary[]> {
  return this.users.list();   // becomes { success: true, data: [...], meta: { totalCount: n } }
}
```

`meta` is **always present**, even when empty, so a client never has to test for its existence. Array
payloads get `meta.totalCount` automatically.

To add your own metadata:

```ts
import { withMeta } from "@compliance-kit/common";

return withMeta(users, { totalCount: 412, nextItem: "cursor" });
```

`ResponseMeta` is deliberately open-ended (`[key: string]: unknown`), with `message`, `totalCount`,
`nextItem` and `prevItem` as the documented common fields.

### Why `success` is on both shapes

`success` was originally only on the envelope, where it was **always `true`** and therefore told a client
nothing.

It is now an RFC 9457 §3.2 extension member on every problem body too, so `body.success` is a valid check
on **any** response. That is what asking for the field was for. It costs nothing for a generic
problem-details client, because §3.2 requires consumers to ignore extension members they do not recognise.

### Opting out

`@RawResponse()` suppresses the envelope. Exactly one route uses it, `/.well-known/jwks.json`, because
wrapping a JWK Set breaks every standard consumer.

That bug is worth remembering as a class: it was **invisible from inside the process**. The handler was
correct and a unit test of it passed. Only the bytes on the wire showed
`{"success":true,"data":{"keys":[…]}}`. If you add a route that must emit a standard format, assert on the
wire, not on the handler's return value.

## The error shape, field by field

Every field is exactly as RFC 9457 defines it. Read §3.1 before changing any of them.

| Field | RFC | Meaning |
| --- | --- | --- |
| `type` | §3.1.1 | URI identifying the problem **type**. Dereferencing it should yield documentation, which is why it points into [problems.md](../problems.md) |
| `title` | §3.1.3 | Short summary of the type. **Stable per type**, never occurrence-specific |
| `status` | §3.1.2 | The HTTP status. Advisory, and always derived from the real status |
| `detail` | §3.1.4 | Explanation of **this occurrence**. Where the tenant slug or field name belongs |
| `instance` | §3.1.5 | URI identifying this occurrence. A `urn:uuid:`, which the RFC permits |
| `code` | §3.2 | Extension: the stable machine-readable code to branch on |
| `traceId` | §3.2 | Extension: the occurrence id again, unwrapped, for support workflows |
| `errors` | §3.2 | Extension: present only on validation failures |

### `title` versus `detail` is not a stylistic split

RFC 9457 §3.1.3 requires that `title` "SHOULD NOT change from occurrence to occurrence". So `DomainError`
carries `title` separately from `message`:

```ts
export class TenantNotFoundError extends DomainError {
  constructor(tenant: string) {
    super(
      "Unknown or inactive tenant",              // title: stable, no interpolation
      `Unknown or inactive tenant: ${tenant}`,   // message -> detail: this occurrence
      "TENANT_NOT_FOUND",
    );
  }
}
```

Interpolating request data into `title` breaks the RFC's contract and makes the field useless for grouping.

### `type` is derived from `code`

`TENANT_NOT_FOUND` becomes `<PROBLEM_TYPE_BASE_URI>#tenant-not-found`. The base URI is configurable, and
**you should change it if you fork the kit**, or your API will cite this repository's documentation for
its own errors.

A unit assertion in `problem-details.filter.spec.ts` **reads problems.md** and fails if any code the
filter can emit has no matching heading, so the RFC's promise that the URI yields documentation stays
true rather than aspirational.

This previously overstated what was checked, and the gap was real. The suite only asserted that a
derived `type` matched a regex, which proves the string was built correctly and nothing about whether
the target exists. Four emittable codes (`method-not-allowed`, `not-acceptable`, `payload-too-large`,
`unsupported-media-type`) pointed at headings that had never been written, and the check that would
have caught them was the check being described. **A test that asserts a derived string is not a test
that the target exists.**

## Status codes

| Status | When |
| --- | --- |
| `400` | Fastify could not parse the body, or no tenant was resolved |
| `401` | Missing or invalid credentials: bad token, cross-tenant token, wrong password, no control-plane key |
| `403` | Authenticated but missing a required permission |
| `404` | Unknown route, or unknown/inactive tenant |
| `409` | Conflict: duplicate tenant slug, already-registered email |
| `422` | Well-formed body, unacceptable values |
| `429` | Rate limited or login-throttled |
| `500` | Unexpected. Body carries nothing but a `traceId` |

### 422, not 400, for validation

This differs from the NestJS default on purpose. Fastify already returns 400 for a body it cannot parse, so
using 400 for both would collapse two genuinely different failures: "your JSON is broken" and "your JSON is
fine and the values are wrong". The RFC 9457 §3.2 validation illustration uses 422 the same way.

Validation failures carry field-level detail with RFC 6901 JSON Pointers:

```json
{
  "success": false, "code": "VALIDATION_FAILED", "status": 422,
  "title": "Request validation failed",
  "detail": "One or more fields are invalid",
  "errors": [
    { "detail": "slug must be lowercase, start with a letter, and use only a-z, 0-9, hyphen",
      "pointer": "#/slug" }
  ]
}
```

The pipe runs with `whitelist: true` and `forbidNonWhitelisted: true`, so unknown properties are
**rejected** rather than silently dropped.

## The catch-all filter is a disclosure control

`ProblemDetailsFilter` is `@Catch()` with no argument, so it renders `DomainError`, every `HttpException`
including framework-generated ones, and unknown throws.

For an unknown throw it logs the stack against a `traceId` and returns a body containing **nothing else**.
That is deliberate: without it, a Prisma error, a driver message or raw SQL text can reach the caller. The
`traceId` is what lets support correlate a user's report with the server log line, without the response
carrying internals.

## Adding an error type

1. Subclass `DomainError` with a stable `title`, an occurrence-specific `message`, and a `SCREAMING_SNAKE`
   code.
2. Map the code to a status in the filter.
3. Document it in [problems.md](../problems.md) under a heading whose anchor matches the derived one. **A
   smoke assertion fails if you skip this**, which is the mechanism that keeps the catalogue honest.

## One wiring trap worth knowing

Injection tokens live in `services/auth/src/core/tokens.ts`, a file with **no imports**, and the token
re-export was deliberately removed from `core.module.ts`.

`ProblemDetailsFilter` needs `CONFIG`. Importing that token from `core.module.ts` created a circular
import, which made the token `undefined` at decorator evaluation time. Nest reports that as an unresolvable
dependency "at index [0]", which is a genuinely misleading way to discover a circular import. The
re-export was removed so a future provider cannot reintroduce the cycle by satisfying `@Inject(CONFIG)`
through the module.
