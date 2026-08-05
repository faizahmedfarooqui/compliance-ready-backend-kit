# Rate limiting

Two distinct controls on Redis, the one setting with no safe default, and what happens when Redis is down.

## Two controls, not one

**Request rate limiting** bounds how many requests a client may make. Global, applied by
`RateLimitGuard`, with per-route overrides.

**Login throttling** bounds how many *failed* authentication attempts an account or a source address may
accumulate. Separate counter, separate window, separate purpose.

They are easy to conflate and they defend different things. A rate limit protects the service from load. A
login throttle protects an account from guessing, and the difference shows up in the details: the throttle
counts only failures, clears on success, and keys on the account as well as the address.

## Request rate limiting

`RateLimitGuard` is registered **globally and first**, before anything that touches the database. An
unauthenticated flood should be rejected by the cheapest check available, not after a tenant lookup.

The smoke test asserts this directly: a request rejected by the control-plane guard must **also** carry
rate-limit headers. If the limiter ran after authentication, an attacker could make unlimited
unauthenticated attempts as long as each one failed.

Defaults are 100 requests per 60 seconds per client. Override per route:

```ts
@Post("login")
@RateLimit({ limit: 20, windowMs: 60_000 })
async login(...) {}
```

Current per-route limits:

| Route | Limit |
| --- | --- |
| `POST /api/auth/login` | 20 per minute |
| `POST /api/auth/register` | 10 per minute |
| `POST /api/tenants` | 30 per hour |
| everything else | 100 per minute |
| `GET /api/health` | never throttled |

**`GET /api/health` is exempt on purpose.** A 429'd liveness probe gets your container killed in the
middle of an incident, turning a load spike into an outage.

### Response headers

`x-ratelimit-limit` and `x-ratelimit-remaining` on every response, and `Retry-After` on a 429.

The kit uses the `X-RateLimit-*` names rather than the newer `RateLimit` and `RateLimit-Policy` fields
from the IETF draft, because the draft is not a published standard and the `X-` names are what clients
actually parse today.

`Retry-After` is rounded **up** to a whole second and floored at 1. RFC 9110 §10.2.3 defines
`delay-seconds` as a non-negative integer, so `Retry-After: 0.4` is malformed, and a rounded-down `0`
tells a client to retry immediately, which is the opposite of the intended message.

A 429 body deliberately does not say which limit was hit or how many attempts remain. On the login route
that would confirm to an attacker that an account exists and is worth continuing against.

## The sliding window is one Lua script

The store is written directly against node-redis with Lua rather than using a community adapter. Both
existing Redis adapters for `@nestjs/throttler` deep-import `@nestjs/throttler/dist/...`, which only
resolves because that package ships no `exports` field, so they break on any internal reorganisation.

**Atomicity is the entire point of using a script.** The operation is a read-modify-write: check the
count, then record the attempt. Done as a `GET` then a `SET` from the application, two concurrent requests
both read the old count and both proceed, so the limiter **undercounts exactly during a burst**, which is
to say exactly during an attack. A Lua script runs atomically on the Redis server, so the check and the
record cannot interleave.

The implementation is a sorted set per key: `ZREMRANGEBYSCORE` drops entries older than the window,
`ZCARD` counts what remains, and `ZADD` records the attempt only if it was allowed.

Two details worth knowing:

- **A rejected attempt is not recorded.** No `ZADD` on the reject path, so hammering an already-throttled
  key does not extend the window. Ten failures cost ten members, however many requests follow.
- **Member ids must be unique per process.** A sorted set is keyed by its member, so `ZADD` on an existing
  member *updates its score* rather than adding a second entry. Colliding member ids across processes
  therefore silently undercounted, which was a real bug: two pods generating the same id meant two
  requests counted as one.

Redis replicates script **effects** rather than the script itself, so a replica cannot diverge by
evaluating its own view of the window.

## `TRUST_PROXY`: the one setting with no safe default

This single boolean decides whether rate limiting works at all, and **both values are wrong in some
deployment.**

| Setting | Deployment | Result |
| --- | --- | --- |
| `false` | behind a load balancer | every request appears to come from the balancer, so all traffic shares one bucket and the first busy client rate-limits everybody |
| `true` | no trusted proxy in front | a caller sends `X-Forwarded-For: anything` and gets a fresh bucket per request, defeating the control entirely |

The default is `false` because that failure is **loud**: everyone gets 429s and you notice within minutes.
The other failure is **silent**: the limiter reports healthy and enforces nothing. Turn it on when, and
only when, something you control is appending the header.

The setting is handed to Fastify rather than parsed in the guard, deliberately. `X-Forwarded-For` is a
**list**, and picking the right element is the part everyone gets wrong: the leftmost entry is the one the
client supplied and can say anything, so a naive `split(",")[0]` hands every caller a fresh bucket.
Fastify walks the list from the right against its trusted set.

Both directions have smoke tests.

## Login throttling is a different control

Counted on **failure only** and **cleared on success**, per account and per source address. Ten failures
in fifteen minutes by default.

Counting only failures and clearing on success means an ordinary user who mistypes twice and then succeeds
is never nearer a limit. That is what makes the limit tight enough to matter without generating support
tickets.

Keying on **both** the account and the address matters: account-only lets an attacker spread guesses
across many accounts from one host, and address-only lets a distributed attacker hammer one account.

This follows NIST SP 800-63B-4 §3.2.2, which requires limiting consecutive failed attempts, treats 100 as
an upper bound rather than a target, prefers escalating delay over hard lockout, and requires resetting the
counter on success. The kit's ten is well inside that.

A throttled login is recorded to the tenant's audit chain, so repeated throttling is visible rather than
merely rate-limited.

## When Redis is unreachable

`RATE_LIMIT_FAIL_OPEN` decides, defaulting to **true**: serve the request.

This is a real trade, not an oversight. Failing closed turns a Redis blip into a total outage of the whole
API, **including the login route**, which is a larger incident than the one being prevented. Failing open
means that during a Redis outage there is no rate limiting.

Because that is the worse compliance outcome of the two, the degradation is made **loud**:

- Every occurrence is logged at error level.
- The response carries `x-ratelimit-degraded: true`.
- The `x-ratelimit-*` budget headers are **omitted** rather than filled with a made-up number. Sending a
  limit and remaining count when nothing was checked tells a client a budget was verified when it was not.

Set it to `false` where unmetered access is the greater risk, and accept that Redis then becomes a hard
dependency for serving traffic.

**The general rule the kit follows:** fail open on request tiers for availability, fail closed on auth
tiers, and make the degradation loud either way. A limiter that silently stops limiting is the worst
possible outcome for a control you are claiming.

## Verifying it

`pnpm smoke` asserts a 429 arrives, that `Retry-After` is present and well-formed, that the limiter runs
before authentication, and that `/api/health` is exempt.

A unit test proves the non-vacuity of the atomicity claim by implementing the **naive** GET-then-SET
limiter in the test and asserting that it over-admits. Without that, a passing test of the real limiter
would not tell you the Lua script was doing anything.

## Known limitations

- **Request-level DoS limits are separate** and cover a different attack. See
  [configuration](configuration.md#request-level-denial-of-service-limits) and
  `pnpm smoke:slowloris`.
- **Network-layer DoS protection is not in scope.** COMPLIANCE.md marks that row Not implemented here: it
  belongs to a CDN or WAF in front of the service.
- **No per-tenant quotas.** Limits are per client, not per tenant.
- **No distributed coordination beyond Redis.** One Redis is a single point of failure for the control, and
  `RATE_LIMIT_FAIL_OPEN` is how that is handled rather than solved.

## Control mapping

Rate limiting and login throttling map to PCI-DSS Req 8 (8.3.4, marked unverified) and SOC 2 CC6.6, with
no direct HIPAA technical safeguard: HIPAA handles availability through the contingency-planning
administrative safeguards rather than a technical control. Marked Implemented. Request-level DoS limits
map to SOC 2 CC6.6, also Implemented. See [COMPLIANCE.md](../COMPLIANCE.md).
