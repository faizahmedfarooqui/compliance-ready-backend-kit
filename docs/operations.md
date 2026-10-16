# Operations

Every command, and the runbooks for the things you will actually need to do.

## Command reference

### Development

| Command | Does |
| --- | --- |
| `pnpm install` | Installs and generates both Prisma clients |
| `pnpm build` | Builds all five workspace packages |
| `pnpm typecheck` | Type-checks everything. **Run `pnpm build` first** on a fresh clone |
| `pnpm lint` / `lint:fix` | ESLint |
| `pnpm format` / `format:check` | Prettier |
| `pnpm dev:auth` | Watch mode |
| `pnpm start:auth` | Start the built service |
| `pnpm stop:auth` | Kill whatever holds the port |
| `pnpm restart:auth` | Both |

### Infrastructure

| Command | Does |
| --- | --- |
| `pnpm infra:up` | Postgres on 55432, Redis on 56379 |
| `pnpm infra:down` | Stop them |
| `pnpm infra:reset` | Destroy the volumes and start clean |

### Database

| Command | Does |
| --- | --- |
| `pnpm db:migrate` | Apply master migrations |
| `pnpm db:migrate:dev` | Create a new master migration |
| `pnpm db:generate` | Regenerate both Prisma clients |
| `pnpm db:tenant-ddl` | Re-render `packages/db/sql/tenant-schema.sql` from the tenant schema |
| `pnpm db:seed:admin --tenant <slug\|uuid> --email <email>` | Seed a tenant's first admin. Password from `SEED_ADMIN_PASSWORD` |
| `pnpm clean:test-tenants` | Drop leftover `tenant_smoke_*` databases. Dry run unless `--yes` |

### Keys

| Command | Does |
| --- | --- |
| `pnpm keys:init` | Bootstrap a deployment: one signing key, one encryption key |
| `pnpm keys:rotate --purpose signing\|encryption` | New active key, previous one retires |
| `pnpm keys:list` | Every key, status, and overlap window |
| `pnpm keys:revoke --kid <kid> --reason "…"` | Revoke, removing the material from the row |
| `pnpm keys:decode <token>` | Fully verify a token, then print claims and headers |

### Audit

| Command | Does |
| --- | --- |
| `pnpm audit:verify --master` | Verify the control-plane chain |
| `pnpm audit:verify --tenant <slug\|uuid>` | Verify one tenant's chain |
| `pnpm audit:immutability --master\|--tenant <slug\|uuid>` | Prove the log refuses UPDATE, DELETE, TRUNCATE |
| `pnpm audit:contention --appends 50` | Prove concurrent appends cannot fork the chain |
| `pnpm provisioning:probe` | Prove an interrupted provisioning resumes, and a database built for another tenant is refused |

### Tests

| Command | Does |
| --- | --- |
| `pnpm test` | 347 unit tests, no database needed |
| `pnpm test:coverage` | With coverage thresholds |
| `pnpm test:watch` | The same suite, on file changes |
| `pnpm smoke` | 100 end-to-end checks against a running service |
| `pnpm smoke:slowloris` | Raw-socket check that the request timeout is real |
| `pnpm verify:claims` | Every suite above, reported per compliance control with its citation |
| `pnpm verify:coverage` | Static: fails if a row marked Implemented has no registered evidence |
| `pnpm verify:claims --list` | The evidence registry, without running anything |

`pnpm verify:claims` is the one to hand an evaluator: it runs the real suites and groups the results by
the control each supports rather than by test mechanism. `pnpm verify:coverage` needs no database and
runs in CI on every pull request. See [compliance mapping](compliance.md#verifying-the-claims-yourself).

### Formatting and linting

| Command | Does |
| --- | --- |
| `pnpm lint:fix` | ESLint with `--fix` |
| `pnpm format:check` | Prettier in check mode, which is what CI runs |

## Runbooks

### Bring up a new deployment

```bash
# 1. Master schema
pnpm db:migrate

# 2. Token keys. Without this the service boots and every login fails.
pnpm keys:init

# 3. Start
pnpm start:auth

# 4. First tenant
curl -X POST <host>/api/tenants -H 'content-type: application/json' \
  -H "authorization: Bearer $CONTROL_PLANE_API_KEY" \
  -d '{"slug":"acme","name":"Acme Corporation"}'

# 5. That tenant's first administrator
SEED_ADMIN_PASSWORD='…' pnpm db:seed:admin --tenant acme --email admin@acme.example
```

Steps 2 and 5 are the two that are easy to forget and both fail confusingly. No keys means every login
returns an error about no active signing key. No seeded admin means a tenant nobody can log into, because
provisioning deliberately creates no users.

### Rotate a signing key

```bash
pnpm keys:list                       # note the current active kid
pnpm keys:rotate --purpose signing
pnpm keys:list                       # expect 1 active + 1 retiring, with an "until" timestamp
```

No restart is needed. `KeyRegistryService` refreshes on a 60 second timer, so a running service picks up
the new key on its own. Tokens signed by the old key keep verifying until its `not_after`, which is set to
`now + accessTtl + clockTolerance`.

**Do not revoke the retiring key before that timestamp.** Tokens still in the wild reference it, and
revoking removes the material, so they stop verifying. Revoking the **active** key is refused outright, because it would leave the
service unable to issue anything.

### Verify an audit chain

```bash
pnpm audit:verify --master
pnpm audit:verify --tenant acme
```

`OK` plus a head hash means the chain is internally consistent from genesis. `EMPTY` means nothing has been
recorded, which is not the same as OK. A break is reported with the `seq` where it was found.

**Record the head hash somewhere the database cannot reach.** The chain cannot detect a full tail rewrite by
someone who can edit rows and recompute every hash forward; comparing the head against an externally held
value is what closes that. The kit does not anchor it for you.

### Prove the audit log is append-only

```bash
pnpm audit:immutability --master
```

Attempts UPDATE, DELETE, TRUNCATE and a chain fork, and requires each to be refused with the right
SQLSTATE. Safe against a live chain: every destructive attempt is wrapped in a transaction that is rolled
back, so a missing trigger is *reported* rather than demonstrated.

It refuses to run against an empty chain, because the row triggers would never fire and both checks would
pass vacuously.

### Investigate a suspected tampering

1. `pnpm audit:verify --tenant <slug|uuid>`. A reported break names the first bad `seq`.
2. Compare the printed head hash with your externally recorded value. If the chain verifies but the head
   differs from what you recorded, that is a **full rewrite**, which is exactly the case the chain alone
   cannot see.
3. `pnpm audit:immutability --tenant <slug|uuid>` to check the enforcement is still in place. A trigger that has
   been dropped is how a rewrite became possible.
4. Search logs for `AUDIT APPEND FAILED`. Appends fail open, so a gap may be an outage rather than an
   attack, and that log line carries every field needed to reconstruct what was not recorded.

### Diagnose a login that will not work

Work down this list; it is roughly in order of likelihood.

| Symptom | Cause |
| --- | --- |
| Error about no active signing key | `pnpm keys:init` was never run |
| `404 TENANT_NOT_FOUND` | Wrong slug, or the tenant is still `provisioning`: see [the next runbook](#recover-a-provisioning-that-failed) |
| `401 INVALID_CREDENTIALS` for a user you are sure exists | Provisioning creates no users; seed the admin |
| `429` immediately | Login throttle from earlier failures. Ten failures per 15 min, cleared on success |
| `400 TENANT_CONTEXT_MISSING` | Missing `x-tenant-id` |
| `401 CROSS_TENANT_TOKEN` | The token belongs to a different tenant than the header names |
| Everything behaves like an older build | A stale server holds the port. Check `uptimeSeconds` on `/api/health` |

### Recover a provisioning that failed

A `POST /api/tenants` that fails partway, because the cluster was unreachable, the schema transaction
rolled back or the process died, leaves the tenant registered as `provisioning`: not resolvable, and
never served. **Repeat the request with the same slug and the same name.** It resumes where the failed
run stopped and answers `201`, and its `tenant.provisioned` event carries `resumed: "true"`.

Two other answers mean something specific:

- **`409 TENANT_PROVISIONING_IN_PROGRESS`**: another request is provisioning that slug right now. Wait
  for it to finish, then repeat the request.
- **A `500` whose log line names `TenantDatabaseConflictError`**: the tenant's database name is taken by
  a database this provisioning did not build, either one marked for a different tenant or one holding the
  tenant schema with no marker. It is refused and left untouched, because it may hold another tenant's
  users and audit log. Find out what it is before changing anything. Once the name is free, repeating
  the request resumes the provisioning.

One case of the second is benign: a tenant stuck in `provisioning` by a version of the kit from before the
marker, whose database was fully built before the failure, so it holds the schema and no marker. A tenant
that never became `active` cannot have had users or audit events, because both need it to resolve, so if
its database has none, nothing in it belongs to anyone:

```sql
-- in the tenant's database
SELECT (SELECT count(*) FROM users) AS users, (SELECT count(*) FROM audit_events) AS events;
-- both 0: mark it for its row (the id from `SELECT id FROM tenants WHERE slug = '<slug>'` on the master)
COMMENT ON DATABASE "tenant_<slug>" IS 'crbk-tenant:<row id>';
```

Then repeat the request. Any other count means the database held a real tenant: do not mark it.

### Clean up after testing

```bash
pnpm clean:test-tenants        # lists what it would drop
pnpm clean:test-tenants --yes  # actually drops
pnpm infra:reset               # nuclear: destroys volumes
```

`clean:test-tenants` scans `pg_database` rather than the registry, so it also collects databases orphaned by
an interrupted provisioning run, and it refuses to touch anything outside the known test prefixes.

## Deployment notes

The kit **does not ship a container image or deployment guidance yet.** That is the current top priority,
and until it lands, the notes below are what you need to know.

- **TLS terminates upstream.** The service speaks plain HTTP and assumes a load balancer or service mesh in
  front. COMPLIANCE.md marks encryption in transit "Not implemented here", which means satisfied outside
  this repository or not at all.
- **Set `KEEP_ALIVE_TIMEOUT_MS` above your proxy's idle timeout.** If the proxy reuses a socket the server
  just closed, clients get 502s that appear in no application log. AWS ALB idles at 60s; the default here is
  72s.
- **Decide `TRUST_PROXY` deliberately.** Behind a balancer it must be `true` or all traffic shares one rate
  limit bucket. Without a trusted proxy it must stay `false` or the limiter can be bypassed with a header.
  See [rate limiting](rate-limiting.md#trust_proxy-the-one-setting-with-no-safe-default).
- **Turn `API_DOCS_ENABLED` off** unless you mean to publish a complete route map.
- **`enableShutdownHooks` is on**, so `SIGTERM` closes database pools rather than dropping them.
- **`GET /api/health` is liveness only** and never touches the database. A readiness probe that checks
  dependencies does not exist yet, so do not point one at this route and assume it covers Postgres.
- **Run the service as a restricted Postgres role if you can**, and there is now a file for it:
  `packages/db/sql/restricted-role.sql`. The immutability SQL already `REVOKE`s UPDATE, DELETE and
  TRUNCATE, but that layer only bites for a role that is neither the table owner nor a superuser, so in
  the default single-role setup it is documentation of intent. Applied, and with the service connecting as
  `crbk_app`, those three statements fail with SQLSTATE 42501 before the trigger is consulted, which was
  verified rather than assumed. Two caveats worth reading first: the role cannot provision tenants,
  because `CREATE DATABASE` needs `CREATEDB`, and the script refuses to run if `crbk_app` owns
  `audit_events`, since an owner keeps those privileges whatever is revoked. Full procedure and the
  trade-off table are in [deployment](deployment.md#the-restricted-role).
