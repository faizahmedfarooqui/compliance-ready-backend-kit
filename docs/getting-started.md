# Getting started

From a fresh clone to an authenticated request, with the steps that are easy to miss called out.

## Prerequisites

- **Node 24.** The current LTS line. `.nvmrc` pins it and CI reads that same file, so the two cannot
  drift. `nvm use` picks it up.
- **pnpm 9.** The repository is a pnpm workspace; npm and yarn will not resolve the
  `@compliance-kit/*` links.
- **Docker.** For local Postgres and Redis. Nothing else uses it.

## Install and run

```bash
cp .env.example .env          # non-secret local defaults
pnpm install                  # also generates the two Prisma clients
pnpm infra:up                 # Postgres on 55432, Redis on 56379
pnpm db:migrate               # apply the master schema
pnpm keys:init                # generate the token signing and encryption keys
pnpm build
pnpm start:auth               # listens on :3011
```

**`pnpm keys:init` is not optional.** The service issues nested JWTs using keys held in the
`config_keys` table, and that table starts empty. Skip this step and the service boots fine but every
login fails, because there is no active signing key to mint with. It is a deliberate operational step
rather than something a migration does: a migration is committed to git and replayed against a shadow
database, so any key it generated would be identical in every environment and therefore public. See
[key management](key-management.md).

The ports deliberately avoid 5432, 6379, 3000 and 3001, because this kit is usually evaluated on a
laptop that already runs another Postgres. Override with `POSTGRES_PORT`, `REDIS_PORT` and `PORT`.

Check it is up:

```bash
curl localhost:3011/api/health
```

## Verify the install

```bash
export CONTROL_PLANE_API_KEY='<the value from your .env>'
pnpm smoke
```

92 end-to-end checks against the running service, covering tenant isolation, cross-tenant token
rejection, token forgery, the published JWKS, the response contract, and the audit chains.

**`pnpm smoke` reads `CONTROL_PLANE_API_KEY` from the shell environment, not from `.env`.** The
service itself loads `.env`; the test script deliberately does not, because CI has no `.env` file, and
under `set -e` an unset variable would abort the whole script rather than fail one assertion. If you
skip the export, provisioning returns 401 and roughly a dozen checks fail with
`CONTROL_PLANE_UNAUTHORIZED`, which looks like a broken install and is not one.

Other checks worth running once, each covering something the smoke test structurally cannot:

```bash
pnpm test                       # 248 unit tests, no database needed
pnpm smoke:slowloris            # raw-socket check that the request timeout is real
pnpm audit:contention           # 50 concurrent appends; asserts the chain cannot fork
pnpm audit:immutability --master # asserts the audit log refuses UPDATE, DELETE and TRUNCATE
```

See [testing](testing.md) for why each of those is a separate tool rather than another smoke step.

## Your first tenant, by hand

The smoke test does all of this; doing it once yourself is the fastest way to understand the shape of
the API.

### 1. Provision a tenant

This creates a dedicated database, applies the tenant schema, seeds the RBAC catalogue and the
`tenant-admin` role, installs the audit-log triggers, then marks the tenant active. It creates **no
users**.

```bash
curl -X POST localhost:3011/api/tenants \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $CONTROL_PLANE_API_KEY" \
  -d '{"slug":"acme","name":"Acme Inc"}'
```

The `authorization` header is required. `POST /api/tenants` creates databases, so it sits behind the
control-plane credential; without it you get 401 `CONTROL_PLANE_UNAUTHORIZED`. See
[the control plane](multi-tenancy.md#the-control-plane-is-a-separate-trust-boundary).

### 2. Seed the first administrator

```bash
SEED_ADMIN_PASSWORD='correct-horse-battery-staple' \
  pnpm db:seed:admin --tenant acme --email admin@acme.example
```

A separate, deliberate step. `POST /api/auth/register` is unauthenticated, so "the first user to
register becomes the admin" would be a land-grab race for anyone who learned a tenant slug. The seed
file is idempotent, so running it twice is safe.

### 3. Log in

Every tenant-scoped call carries `x-tenant-id`.

```bash
curl -X POST localhost:3011/api/auth/login \
  -H 'content-type: application/json' -H 'x-tenant-id: acme' \
  -d '{"email":"admin@acme.example","password":"correct-horse-battery-staple"}'
```

The response is `{ success: true, data: { accessToken }, meta: {} }`. The token's lifetime is not in the
body; it is `JWT_ACCESS_TTL_SECONDS` (900 by default) and is carried as the `exp` claim inside the
token.

### 4. Use the token

```bash
curl localhost:3011/api/users \
  -H 'x-tenant-id: acme' \
  -H "authorization: Bearer $TOKEN"
```

### 5. Inspect the token, if you want to see inside it

The access token is a nested JWT: signed, then **encrypted**. Pasting it into jwt.io shows you
nothing, because there is no readable payload without the key. That is the point.

```bash
pnpm keys:decode "$TOKEN"
```

This fully verifies both layers before printing anything. It is not a decoder, and there is
deliberately no decode-without-verify helper anywhere in the kit: that is the RFC 8725 §2.3 mistake
wearing a helpful name. See [authentication](authentication.md).

## Stopping and resetting

```bash
pnpm stop:auth       # kills whatever holds :3011
pnpm restart:auth    # stop, then start
pnpm infra:reset     # wipe Postgres and Redis volumes, start clean
pnpm clean:test-tenants   # drop leftover tenant_smoke_* databases (dry run; --yes to apply)
```

`stop:auth` kills by **port**, not by process name, and that distinction is not pedantry.
`nest start --watch` runs the app as `node --enable-source-maps .../dist/main`, so a plausible
`pkill -f "node dist/main.js"` matches nothing, exits 0, and leaves a stale server holding the port
for your next test run to talk to.

Which brings up the failure mode most likely to waste your afternoon.

## If results look impossible, check which server you are talking to

A stale process holding `:3011` answers every request happily, so a test suite pointed at it reports
passes for code that is not running. This is common enough that `pnpm smoke` has a dedicated step 0
that refuses to proceed: it checks the reported version against `services/auth/package.json`, requires
uptime under `SMOKE_MAX_UPTIME` (default 1800s), and requires that exactly one process holds the port.

You can check by hand at any time:

```bash
curl -s localhost:3011/api/health | jq '.data.uptimeSeconds'
```

If that number is much larger than the age of your last `pnpm build`, you are talking to an old
server. `pnpm restart:auth` fixes it.

## Where to go next

- [Configuration](configuration.md) for what every environment variable does.
- [Request lifecycle](request-lifecycle.md) to see what happens between the socket and your handler.
- [API reference](api-reference.md) for every route and its guards.
