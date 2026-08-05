# Multi-tenancy

Database-per-tenant: how it works, why it was chosen over shared-table RLS, and what it costs.

## The model

Two planes.

**The control plane** is a single **master database**. It holds the tenant registry (`tenants`), the
key registry (`config_keys`), and its own audit chain for control-plane events.

**The data plane** is **one Postgres database per tenant**. Each holds that tenant's users, roles,
permissions, grants, and its own independent audit chain.

```
master database                    tenant_acme                tenant_globex
  tenants                            users                      users
  config_keys                        roles                      roles
  audit_events (control plane)       permissions                permissions
                                     role_permissions           role_permissions
                                     user_roles                 user_roles
                                     audit_events (acme)        audit_events (globex)
```

A request names its tenant with the `x-tenant-id` header, carrying either the slug or the uuid.
`TenantGuard` resolves it against the master registry and attaches the resolved tenant plus a client
for that tenant's database to the request.

## Why database-per-tenant

The alternative most kits pick is one shared table set with a `tenant_id` column and Postgres
row-level security. That is a reasonable design and it is not this one.

**Isolation is enforced by the database, not by application code.** With a shared table, every query
in the system must carry the right predicate, forever, including the one written at 6pm by someone
who did not know the rule. RLS improves that considerably but still depends on session variables being
set correctly on every connection checkout, and a pooled connection that keeps a previous request's
setting is a cross-tenant read.

With database-per-tenant, a query against the wrong tenant cannot return another tenant's rows because
the connection is not attached to a database containing them. The failure mode changes from "silently
returns the wrong data" to "the table does not exist".

**It is the right default for regulated workloads.** You generally cannot keep two companies' regulated
data in the same database and satisfy a serious assessor with "our application always adds a WHERE
clause". Per-tenant databases also make per-tenant export, data residency, and deletion coherent
operations rather than large delete statements you have to trust.

**Per-tenant recovery.** Restoring one tenant to a point in time is restoring one database, not
surgically extracting rows from a shared backup.

### What it costs, stated plainly

- **Connection pressure.** One pool per active tenant. The kit's pool cache is currently unbounded;
  see the limitations below.
- **Migrations must fan out.** A schema change has to be applied to every tenant database. **The kit
  does not do this yet**: only newly provisioned databases get the current DDL. A per-tenant migration
  runner is on the roadmap and its absence is a real limitation, not a detail.
- **No cross-tenant queries.** Aggregate reporting across tenants needs a separate pipeline.
- **No global ordering of audit events across tenants.** Discussed in [audit log](audit-log.md).

## Provisioning a tenant

`POST /api/tenants` does the following, and the ordering is deliberate:

1. Derive a safe database name from the slug (`tenant_<slug>`, lowercased, non-alphanumerics to
   underscores) and validate it against a strict identifier pattern.
2. Insert the registry row with status `provisioning`.
3. `CREATE DATABASE`.
4. Inside one transaction against the new database: apply the generated tenant DDL, apply
   `sql/audit-immutability.sql`, seed the permission catalogue and the `tenant-admin` role.
5. Mark the registry row `active`.
6. Append a `tenant.provisioned` event to the **master** chain.

The status field is what makes step 3 and 4 safe to fail: a tenant stuck in `provisioning` is not
resolvable, so a half-built database is never served. `TenantGuard` resolves only `active` tenants.

**Provisioning creates no users.** That is a security decision, covered below.

### The control plane is a separate trust boundary

`POST /api/tenants` creates databases, so it sits behind `ControlPlaneGuard`, which requires
`CONTROL_PLANE_API_KEY` as a bearer credential. This route shipped unauthenticated once; that was the
single worst hole in the kit's history, and the credential is now required with no default so the route
cannot be open merely because nobody set a variable.

Note what the credential is and is not. It authenticates the *bearer*, not a person. It cannot say
which operator called. This is why `tenant.provisioned` is recorded with actor type `control_plane` and
**no actor id**, and why the database refuses to let it carry one. See
[audit log](audit-log.md#what-the-control-plane-chain-cannot-tell-you).

### Why the first administrator comes from a seed file

`pnpm db:seed:admin --tenant acme --email admin@acme.example`, with the password in
`SEED_ADMIN_PASSWORD`.

Not from provisioning, and emphatically not from "the first user to register wins".
`POST /api/auth/register` is unauthenticated, so that shortcut is a land-grab race for anyone who
learns a tenant slug: whoever registers first becomes the administrator of a company they do not work
for. Making the first admin a deliberate operator action removes the race entirely.

The seed is idempotent, so re-running it is safe.

## Resolving a tenant

`TenantGuard` runs first in every tenant-scoped chain. It reads `x-tenant-id`, calls
`ConnectionManager.resolveTenant`, and attaches the result. `TenantContextService` is
`Scope.REQUEST` and exposes `tenant` and `db` off the request, throwing
`TenantContextMissingError` when nothing resolved a tenant.

One implementation detail with a security edge. `resolveTenant` accepts a slug **or** a uuid, and an
earlier version OR-ed a uuid column against a slug in a single query. Every slug lookup then raised
Postgres error 22P02 (invalid input syntax for type uuid), which surfaced as a **500 and an error-log
flood** rather than a clean 404. The same bug class is why `config_keys.kid` is `TEXT` rather than
`uuid`: an attacker-supplied non-uuid value against a uuid column turns a 401 into a 500.

## The two Prisma schemas

Two schemas, two generated clients, one config each.

`prisma/master/schema.prisma` migrates normally with `pnpm db:migrate`.

`prisma/tenant/schema.prisma` **has no single database to migrate**, because there are N of them and
they are created at runtime. So it is rendered to SQL:

```bash
pnpm db:tenant-ddl     # regenerates packages/db/sql/tenant-schema.sql
```

That file is **generated but committed**, and CI fails the build if it is stale. Regenerate it whenever
the tenant schema changes, or new tenants get a schema nobody reviewed.

The two clients are separately generated types that happen to have identical shapes for the tables they
share. That is why the audit writer accepts a narrow structural interface rather than either client
type: see [audit log](audit-log.md#one-writer-two-clients).

## Known limitations

- **The tenant pool cache is unbounded.** Every resolved tenant keeps a pool. Safe eviction needs
  refcounting, because closing a pool while a request holds a client from it breaks that request. Left
  visible rather than done subtly wrong.
- **Existing tenant databases are never migrated.** Only new ones get current DDL.
- **The pool has an `error` listener, and it must keep it.** An idle-connection error with no listener
  crashes the Node process, which with database-per-tenant takes every tenant down with it.
- `pnpm smoke` leaves real `tenant_smoke_*` databases behind. `pnpm clean:test-tenants` removes them
  (dry run by default), and `pnpm infra:reset` wipes everything.

## Control mapping

Database-per-tenant isolation is the row for HIPAA 164.312(a)(1), PCI-DSS Req 7 and SOC 2 CC6.1, marked
Implemented. The control-plane authorization row is HIPAA 164.312(a)(1) and 164.308(a)(4), PCI Req 7,
SOC 2 CC6.3. See [COMPLIANCE.md](../COMPLIANCE.md) and [the compliance guide](compliance.md).
