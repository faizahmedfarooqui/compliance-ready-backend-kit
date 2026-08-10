# Configuration

Every setting, what it controls, and which ones have no safe default.

## How configuration works

One validated entry point, `loadConfig()` in `@compliance-kit/config`, backed by a zod schema. It
runs at boot and **throws on anything missing or malformed**, so a misconfigured deployment never
starts and never half-works.

```ts
import { loadConfig, loadLocalDotenv } from "@compliance-kit/config";

loadLocalDotenv();          // local development only; a no-op when NODE_ENV=production
const config = loadConfig(); // typed AppConfig, or throws with every problem listed
```

Two rules that matter more than the list below.

**Nothing reads `process.env` at runtime.** Values are read once, validated, and injected as a typed
`AppConfig`. Reaching for `process.env` inside a service defeats the validation and hides a
dependency the boot check cannot see.

**In production, secrets do not come from the environment.** `loadConfig` accepts any record, so the
intended production path is: resolve secrets from KMS or Secrets Manager first, merge them into the
record, pass that to `loadConfig`, and never leave them in `process.env`. Swap the source, not the
shape. Today the kit ships no KMS adapter, which is why the key-encrypting key still arrives as a
variable; see [key management](key-management.md#what-is-not-done-yet).

`loadLocalDotenv()` walks up from the working directory looking for a `.env`, because a service is
started from `services/auth` while the developer's `.env` sits at the repo root. It is skipped
entirely when `NODE_ENV=production`, and dotenv never overwrites a variable that is already set, so a
real environment always wins over the file.

## Required, with no default

These seven have no fallback. The service refuses to boot without them, on purpose.

| Variable | What it is |
| --- | --- |
| `MASTER_DATABASE_URL` | Postgres URL for the master (control-plane) database holding the tenant registry and `config_keys` |
| `TENANT_CLUSTER_URL` | Postgres URL for the cluster where per-tenant databases live. Often the same cluster as the master |
| `JWT_ISSUER` | The `iss` claim, and what verification requires |
| `JWT_AUDIENCE` | The `aud` claim. Rejects a token minted for a different service that happens to share these keys |
| `REDIS_URL` | Redis, used for rate limiting and login throttling. Must be Redis 6 or newer: the client negotiates RESP3, which needs a server that answers `HELLO` |
| `KEY_ENCRYPTION_KEY` | The KEK that wraps every key in `config_keys`. See below |
| `CONTROL_PLANE_API_KEY` | Bearer credential for control-plane routes. See below |

### The two 256-bit keys

`KEY_ENCRYPTION_KEY` and `CONTROL_PLANE_API_KEY` are both base64url-encoded 256-bit values, meaning
**exactly 43 characters** with no padding. Generate either with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

The length is pinned in the schema rather than checked as "at least 16 characters", because the
algorithms require an exact key length and `jose` does not enforce a minimum itself: it will sign
with a 4-byte key without complaint.

`CONTROL_PLANE_API_KEY` is **required with no default**, and that is the control. An optional
credential leaves the route open whenever it is unset, which is the state `POST /api/tenants` shipped
in: a route that creates databases, reachable by anyone who could open a socket. A control that
exists only when someone remembers to configure it is not a control.

Be clear-eyed about what a shared secret buys you. It authenticates the *bearer* and nothing else: it
does not identify which operator called, cannot be scoped to one action, is replayable by anyone who
reads it from a log or shell history, and rotating it invalidates every caller at once. It is the
right primitive for a kit and the wrong one for a mature deployment, which should use mutual TLS or a
signed operator token carrying an identity. This is why control-plane audit events record no actor id:
see [audit log](audit-log.md#what-the-control-plane-chain-cannot-tell-you).

## Settings with defaults

### Service

| Variable | Default | Notes |
| --- | --- | --- |
| `NODE_ENV` | `development` | `development` \| `test` \| `production` |
| `PORT` | `3011` | Deliberately not 3000 or 3001 |
| `PROBLEM_TYPE_BASE_URI` | this repo's `problems.md` | Base for RFC 9457 `type` URIs. **Change it if you fork**, or your API cites someone else's docs for its own errors |
| `API_DOCS_ENABLED` | `true` | Publishes the OpenAPI document and the browsable UI at `/docs` |

`API_DOCS_ENABLED` defaults on because an undiscoverable API is one nobody adopts. Turn it **off** in
production unless you mean to publish it: an OpenAPI document is a complete map of every route,
parameter and constraint, which is exactly its value to an author and to an attacker. Left on with
`NODE_ENV=production` the service logs a warning rather than quietly overriding your setting.

### Tokens

| Variable | Default | Notes |
| --- | --- | --- |
| `JWT_ACCESS_TTL_SECONDS` | `900` | 15 minutes. Permissions are baked into the token at login, so this is also the revocation lag |
| `JWT_CLOCK_TOLERANCE_SECONDS` | `5` | Leeway on `exp` and `iat`, and also the length of a key-rotation overlap |

`JWT_CLOCK_TOLERANCE_SECONDS` does double duty deliberately. A retiring key must stay verifiable for
as long as a token it signed can still be presented, which is the TTL plus this tolerance. Shorter
kills live tokens at rotation; absent means the overlap never ends.

### Rate limiting

| Variable | Default | Notes |
| --- | --- | --- |
| `TRUST_PROXY` | `false` | Whether to believe `X-Forwarded-For`. **No safe default.** See below |
| `RATE_LIMIT_DEFAULT_LIMIT` | `100` | Requests per client per window on routes with no explicit limit |
| `RATE_LIMIT_DEFAULT_WINDOW_MS` | `60000` | |
| `LOGIN_THROTTLE_LIMIT` | `10` | Failed logins per account and per source address before both are throttled |
| `LOGIN_THROTTLE_WINDOW_MS` | `900000` | 15 minutes |
| `RATE_LIMIT_FAIL_OPEN` | `true` | Serve (true) or reject (false) when Redis is unreachable |

**`TRUST_PROXY` is the one setting where both values are wrong in some deployment**, so it has to be a
deliberate choice. Left `false` behind a load balancer, every request appears to come from the
balancer and all your traffic shares one bucket, so the first busy client rate-limits everybody. Set
`true` without a trusted proxy in front, and a caller sends `X-Forwarded-For: anything` to get a fresh
bucket per request, defeating the control silently.

The default is `false` because that failure is *loud*: everyone gets 429s and you notice in minutes.
The other failure is silent, and the limiter reports healthy while enforcing nothing. Turn it on when,
and only when, something you control is appending the header.

Full discussion in [rate limiting](rate-limiting.md).

### Request-level denial-of-service limits

Four values that together are the whole request-level DoS surface. They are declared here rather than
inherited so that anyone can say what the service tolerates without reading Fastify's source.

| Variable | Default | Bounds |
| --- | --- | --- |
| `REQUEST_TIMEOUT_MS` | `30000` | Time a client gets to send an entire request, headers and body. The slowloris defence |
| `CONNECTION_TIMEOUT_MS` | `75000` | Socket inactivity. **Must exceed `KEEP_ALIVE_TIMEOUT_MS`** |
| `KEEP_ALIVE_TIMEOUT_MS` | `72000` | How long an idle keep-alive socket is held |
| `BODY_LIMIT_BYTES` | `1048576` | Maximum request body |
| `CONNECTIONS_CHECKING_INTERVAL_MS` | `5000` | How often Node sweeps for expired requests. **Must be less than `REQUEST_TIMEOUT_MS`** |

`REQUEST_TIMEOUT_MS` is the setting that stops a client which completes its headers, declares a
`Content-Length`, then sends the body one byte at a time. No individual gap is suspicious and no
inactivity timeout fires, so nothing else bounds it. **Raise it if you add file upload**: a 1 MiB body
over a slow mobile link legitimately takes minutes and this will cut it off.

`KEEP_ALIVE_TIMEOUT_MS` is longer than it looks like it should be because it must exceed the idle
timeout of whatever sits in front. If a proxy reuses a socket the server just closed, the client gets
a 502 that appears in no application log. AWS ALB idles at 60s by default, hence 72s. Lower this only
after lowering the proxy's.

`CONNECTIONS_CHECKING_INTERVAL_MS` is the *granularity* of the request timeout, not a separate limit.
Node walks the connection list on an interval rather than arming a timer per request, so the effective
deadline is the timeout plus up to one interval. Node's own default is 30s, which would make a 30s
request timeout fire anywhere between 30 and 60 seconds.

## Two invariants checked at boot

The schema refuses these combinations rather than trusting the comments:

1. **`CONNECTION_TIMEOUT_MS` must be greater than `KEEP_ALIVE_TIMEOUT_MS`.** Set lower, the socket
   inactivity timeout preempts the keep-alive timeout and silently becomes the rule governing idle
   connections, making `KEEP_ALIVE_TIMEOUT_MS` dead config and reintroducing the load-balancer race.
2. **`CONNECTIONS_CHECKING_INTERVAL_MS` must be less than `REQUEST_TIMEOUT_MS`.** Otherwise the sweep
   granularity rather than the timeout decides when a slow request is cut off.

Both would otherwise start, serve traffic, and be wrong in a way nothing surfaces.

## A Fastify option that silently does nothing

Worth knowing if you change the timeouts, because it looks like duplication in `main.ts` and is not.

Fastify's own `requestTimeout` option does not work alone for any value under 60s, and fails silently.
Node derives `headersTimeout = min(60_000, requestTimeout)` inside `http.createServer` and validates
`headersTimeout <= requestTimeout` there and only there. Fastify creates the server first, then
assigns `server.requestTimeout` afterwards without touching `headersTimeout`. A configured 30s
therefore leaves the pair at headersTimeout 60000 / requestTimeout 30000, violating the invariant the
constructor would have rejected, and Node's expiry sweep then never expires anything.

So the timeout is passed **twice**: once through `http` so the constructor derives a consistent
`headersTimeout`, and once at the top level so Fastify's post-construction assignment writes the same
value instead of its default of 0. Every other combination leaves the body unbounded, which is how the
hole survived being fixed once already.

`pnpm smoke:slowloris` asserts this by socket, not by reading.
