# Request lifecycle

Every stage a request passes through, in order, and where your own code belongs.

## The whole path

```
socket
  └─ Fastify: requestTimeout, connectionTimeout, keepAliveTimeout, bodyLimit
       │        (a slow or oversized request dies here, before Nest sees it)
       └─ JSON parse            malformed body -> 400, rendered by ProblemDetailsFilter
            └─ route match      no match      -> 404, rendered by ProblemDetailsFilter
                 └─ RateLimitGuard (global)          429 + Retry-After
                      └─ TenantGuard                 x-tenant-id -> tenant + db
                           └─ AccessTokenGuard       decrypt, verify, bind tid
                                └─ PermissionsGuard  required permissions
                                     └─ ValidationPipe (global)   422 on a bad DTO
                                          └─ your handler
                                               └─ ResponseEnvelopeInterceptor  { success, data, meta }
```

Errors from anywhere in that stack land in `ProblemDetailsFilter`, which renders every one of them as
`application/problem+json`. See [the response contract](responses.md).

## Stage by stage

### 1. Fastify server limits

Before any application code. Four limits bound the request-level denial-of-service surface: how long a
client may take to send a request, how long an idle socket lives, and how large a body may be. They are
explicit config values rather than framework defaults, and one of them requires a workaround for a
Fastify option that silently does nothing. See
[configuration](configuration.md#request-level-denial-of-service-limits).

A slowloris attack is refused here with a 408 and no application code involved.

### 2. Rate limiting, globally, first

`RateLimitGuard` is registered globally and runs before anything that touches the database. That
ordering is the point: an unauthenticated flood should be rejected by the cheapest check available.

The smoke test asserts this directly, by checking that a request rejected by the control-plane guard
*also* carries rate-limit headers. If the limiter ran after authentication, an attacker could make
unlimited unauthenticated attempts as long as each one failed.

`GET /api/health` is never throttled. A 429'd liveness probe gets your container killed in the middle
of an incident.

Details in [rate limiting](rate-limiting.md).

### 3. `TenantGuard`

Reads `x-tenant-id`, resolves it against the master registry, and attaches the tenant and a client for
its database. Only `active` tenants resolve. An unknown or inactive tenant is 404
`TENANT_NOT_FOUND`; a missing header is 400 `TENANT_CONTEXT_MISSING`.

### 4. `AccessTokenGuard`

Extracts the bearer token, decrypts the outer JWE, verifies the inner JWS, checks `iss`, `aud`, `exp`
and `iat`, and **requires that the token's `tid` claim equals the tenant just resolved.**

That last check lives here, in the same step as authentication, rather than in a guard of its own. A
separate guard is a guard someone can leave out of a chain, and the hole it closes is real: a validly
signed token for tenant A presented with `x-tenant-id: B` authenticates a principal who holds no
account in B while carrying A's permissions. Database-per-tenant does not catch it, because the query
is routed correctly to B's database and no data crosses. Physical isolation answers "whose data can
this connection reach"; it does not answer "who is allowed to ask".

It also **fails closed**: no resolved tenant is an error, not a pass. An authenticated route with no
`TenantGuard` in front of it breaks loudly instead of silently skipping the binding.

Details in [authentication](authentication.md).

### 5. `PermissionsGuard`

Reads the permissions declared by `@RequirePermissions` and compares them against the verified claims.
A denial is **recorded to the tenant's audit chain** before the 403 is thrown, which is why this guard
is async.

The cost is a database write on the denial path of every protected route. That is acceptable precisely
because it is the denial path: an allowed request pays nothing, and a caller generating enough denials
for the write to matter is the caller the record exists to document. `AuditService` fails open, so an
unwritable chain slows the rejection rather than turning it into a 500.

Details in [authorization](authorization.md).

### 6. `ValidationPipe`

Global, with `whitelist: true`, `forbidNonWhitelisted: true`, `transform: true`. Unknown properties are
**rejected**, not stripped.

Failures produce **422, not 400**, and carry an `errors` array of RFC 6901 JSON Pointers. This differs
from the NestJS default deliberately: Fastify already uses 400 for a body it cannot parse, so keeping
the two distinct means a client can tell "your JSON is broken" from "your JSON is fine and the values
are wrong".

Note the pipe runs **after** the guards, which is standard NestJS ordering and occasionally surprising:
an unauthenticated request with an invalid body gets 401, not 422.

### 7. Your handler

Return a bare resource. The envelope is added for you.

```ts
@Get()
@TenantAuthenticated(PERMISSION_KEYS.usersRead)
async list(): Promise<UserSummary[]> {
  return this.users.list();
}
```

If you need to say something extra, wrap the payload:

```ts
return withMeta(users, { totalCount: 412 });
```

### 8. `ResponseEnvelopeInterceptor`

Wraps every 2xx in `{ success: true, data, meta }`. Arrays get `meta.totalCount` automatically.

Opt out with `@RawResponse()` when a route must emit a standard format that an envelope would break.
There is exactly one such route today, `/.well-known/jwks.json`: wrapping a JWK Set in
`{ success, data }` breaks every standard consumer, including `jose`'s own `createRemoteJWKSet`.

That bug was invisible from inside the process. The handler was correct and a unit test passed. Only
the bytes on the wire showed `{"success":true,"data":{"keys":[...]}}`.

### 9. `ProblemDetailsFilter`

`@Catch()` with no argument, so it renders everything: `DomainError`, any `HttpException` (including
Nest's 404 for an unmatched route and Fastify's 400 for an unparseable body), and unknown throws.

An unknown throw logs its stack against a `traceId` and returns a body containing nothing else. That is
a disclosure control, not tidiness: it is what stops a driver message or SQL text reaching a caller.

## Where to put your own code

| You want to | Do this |
| --- | --- |
| Protect a tenant-scoped route | `@TenantAuthenticated(PERMISSION_KEYS.something)` |
| Add a permission | Add it to `PERMISSION_KEYS` in `packages/common`, then use it. See [authorization](authorization.md#adding-a-permission) |
| Set a route-specific rate limit | `@RateLimit({ limit: 20, windowMs: 60_000 })` |
| Return extra response metadata | `withMeta(payload, { ... })` |
| Emit a non-enveloped body | `@RawResponse()`, and be sure you need it |
| Add a new error type | Subclass `DomainError`, document it in [problems.md](../problems.md). A smoke assertion fails if the anchor is missing |
| Record an audit event | Inject `AuditService`, call `tenantEvent` or `controlPlaneEvent`. See [audit log](audit-log.md#emitting-an-event) |
| Reach the current tenant's database | Inject `TenantContextService`, use `.db` |

## Two ordering rules that are load-bearing

**Guard order inside `@TenantAuthenticated` is fixed** and the decorator exists to keep it that way:
tenant, then token, then permissions. Drop the first and there is no database to query and no tenant to
bind the token to. Prefer the decorator over assembling `@UseGuards` by hand for anything
tenant-scoped.

**Module order in `app.module.ts` affects guard registration.** `RateLimitModule` is listed before the
feature modules so its global guard registers first, and `AuditModule` before `RbacModule` so the
permissions guard's dependency exists when it is resolved at boot.
