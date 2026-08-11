# Deployment

How to build the container image, apply migrations, and run the service as a restricted database role.

This page exists because the kit could be evaluated on a laptop and not shipped. Everything below has
been run; where something is not implemented, it says so rather than describing an intention.

## The image has three targets

```bash
docker build -t crbk-auth .                        # runtime, the default
docker build -t crbk-auth:migrator --target migrator .
```

| Target | Contains | For |
| --- | --- | --- |
| `builder` | Full workspace, dev dependencies, compiled output | Intermediate |
| `migrator` | `builder` plus the `prisma` CLI | `migrate deploy`, `keys:init`, `keys:rotate` |
| `runtime` | Production dependencies and `dist` only | Serving the API |

**Migrations are deliberately not in the runtime image.** `prisma migrate deploy` needs the `prisma`
CLI, which is a dev dependency the runtime stage excludes. That is the right way round rather than an
inconvenience: a container that serves traffic should not also carry the tool that can rewrite the
schema, and the audit-log design below depends on that separation. An image able to do both would
quietly collapse it.

Three details in the Dockerfile worth knowing before editing it:

- **Debian slim, not Alpine.** `argon2` ships prebuilt binaries against glibc. On musl it compiles from
  source, which means a C toolchain in the image and a build that has to succeed on every architecture
  you deploy to. The password KDF is not the place to accept that.
- **The entry point is `dist/main.js`, not `services/auth/dist/main.js`.** `pnpm deploy` places the
  deployed package at the root of its output and its workspace dependencies under
  `node_modules/@compliance-kit/*`, so the monorepo layout does not survive into the image. The wrong
  path builds a working image that exits immediately with `MODULE_NOT_FOUND`.
- **`pnpm deploy` runs with `--ignore-scripts`, and it is required.** `packages/db`'s `postinstall`
  calls the `prisma` CLI that `--prod` has just excluded. Skipping it is safe because the generated
  clients are already compiled into `dist`.

The image also has to carry `packages/db/sql/*.sql`, because `ConnectionManager` reads
`tenant-schema.sql` and `audit-immutability.sql` at **provisioning** time via
`path.resolve(__dirname, "..", "sql", ...)`. They are runtime inputs, not build artefacts. Omit them
and the service starts, passes its health check, and then fails the first time a tenant is created.

## Running it

```bash
docker run --rm --env-file .env -p 3011:3011 crbk-auth
```

The container runs as the unprivileged `node` user, and `node` is PID 1 so `SIGTERM` reaches it
directly. That matters: the shutdown hooks are what close the pg pools and send Redis `QUIT` instead of
dropping in-flight commands, and they do not run if a shell swallows the signal.

`HEALTHCHECK` probes `/api/health` rather than checking that the process is alive, because those are
different claims here. The service deliberately **boots when Redis is unreachable** and says so, so
process liveness would report a degraded instance as healthy. `/api/health` is exempt from rate
limiting, so probing it cannot consume a caller's budget: a 429'd liveness probe gets the container
killed mid-incident.

## Order of operations for a new environment

```bash
# 1. Schema. Runs as the OWNER role.
docker run --rm --env-file .env crbk-auth:migrator pnpm db:migrate

# 2. Token keys. Not a migration, on purpose: a migration is committed to git and replayed against a
#    shadow database, so any key it generated would be identical everywhere and public.
docker run --rm --env-file .env crbk-auth:migrator pnpm keys:init

# 3. The restricted role, once per database. See below.
psql "$MASTER_DATABASE_URL" -f packages/db/sql/restricted-role.sql

# 4. Serve.
docker run --rm --env-file .env -p 3011:3011 crbk-auth
```

Skipping step 2 produces the most confusing failure available: the service boots cleanly, reports
healthy, and fails every login, because `config_keys` starts empty and a service with no active signing
key cannot mint a token.

## The restricted role

This is the step that changes what the kit can claim, so it is worth understanding rather than pasting.

`audit-immutability.sql` installs three layers, and its own comments admit the third is inert by
default: `REVOKE UPDATE, DELETE, TRUNCATE ... FROM PUBLIC` only bites for a role that is neither a
superuser nor the table's owner, and out of the box the service connects as the role that owns
everything. The immutability probe says the same about its own REVOKE check, in as many words: it
catches a stray `GRANT` and does not confirm the `REVOKE`.

`packages/db/sql/restricted-role.sql` fixes that. Create the role out of band, because no file in this
repository may contain a credential:

```
$ psql "$MASTER_DATABASE_URL"
=# CREATE ROLE crbk_app LOGIN;
=# \password crbk_app
Enter new password for user "crbk_app": ...
```

**Do not pass the password on the command line.** `psql -c "CREATE ROLE ... PASSWORD '...'"` puts the
secret into your shell history, and on some systems into the process list where any local user can read
it. psql's `\password` prompts for it and sends an `ALTER ROLE` with the value already hashed, so the
plaintext never reaches history, the process table, or the server log. A provisioning tool reading from
your secret manager is equally fine; a `-c` one-liner is not.

Then apply the grants, once per database, **as a role that owns the tables** and not as `crbk_app`:

```bash
psql "$MASTER_DATABASE_URL" -f packages/db/sql/restricted-role.sql
# and once per tenant database
psql "$TENANT_CLUSTER_URL/tenant_acme" -f packages/db/sql/restricted-role.sql
```

The file refuses to run if it would be decorative: it raises if `crbk_app` is a superuser, and if
`crbk_app` owns `audit_events`. An owner keeps `UPDATE`, `DELETE` and `TRUNCATE` no matter what is
revoked, so in either case every grant would succeed while enforcing nothing, and a clean run would be
the only evidence you got. That is the failure mode this check exists to make impossible, and owning the
table is not hypothetical: it is exactly what happens if `crbk_app` is given `CREATEDB` and allowed to
provision, since whoever creates the tables owns them.

Then point the service's `MASTER_DATABASE_URL` and `TENANT_CLUSTER_URL` at `crbk_app` rather than at
the owner.

**Verified, not asserted.** Connected as `crbk_app` against a database provisioned by the container:

| Statement on `audit_events` | Result |
| --- | --- |
| `SELECT` | permitted |
| `INSERT` | permitted |
| `UPDATE` | `ERROR: 42501: permission denied for table audit_events` |
| `DELETE` | `ERROR: 42501: permission denied for table audit_events` |
| `TRUNCATE` | `ERROR: 42501: permission denied for table audit_events` |

`42501` is `insufficient_privilege`, and it is raised **before the trigger is consulted**. So two
independent mechanisms now have to be defeated instead of one, and the privilege layer keeps working if
a trigger is ever dropped, which is precisely the case a trigger cannot defend against.

The grants are listed table by table rather than with `GRANT ... ON ALL TABLES`, and that is the point
of the file. `ON ALL TABLES` would include `audit_events` and hand it `UPDATE` and `DELETE`, producing a
setup that looks restricted, survives a casual review, and enforces nothing where it matters.

### The honest limit: provisioning wants the opposite privilege

`ConnectionManager` runs `CREATE DATABASE` at runtime to provision a tenant, then creates that tenant's
tables. So the provisioning path needs `CREATEDB`, and whichever role creates those tables **owns**
them, and an owner is exempt from `REVOKE`.

`crbk_app` deliberately does not have `CREATEDB` (`rolcreatedb = f`, checked). The consequences are
real and worth stating plainly:

- Point the service at `crbk_app` and **runtime tenant provisioning stops working**. `POST /api/tenants`
  will fail.
- Grant `CREATEDB` to `crbk_app` and provisioning works, but every tenant table it creates is owned by
  the role you were trying to restrict, so inside tenant databases the privilege layer is back to being
  documentation. The master database keeps the benefit either way, since nothing creates tables there
  at runtime.

Provisioning and serving want different privileges, and this kit currently reaches both through one
`TENANT_CLUSTER_URL`. Splitting them, a privileged URL used only by the provisioning path and a
restricted one for request handling, is a configuration and code change that **is not implemented**.
Until it is, pick per environment:

| If you | Then |
| --- | --- |
| Provision tenants out of band (an operator or pipeline step) | Run the service as `crbk_app` everywhere. Strongest posture, and `POST /api/tenants` is unavailable |
| Need runtime self-service provisioning | Run as the owner, or grant `CREATEDB`. The triggers still fire for owners, so the log stays tamper-evident; it is not privilege-enforced inside tenant databases |

Either way the master chain gets the privilege layer, and either way the hash chain and the triggers
apply. What changes is how many independent mechanisms an attacker has to defeat.

## What this page does not give you

- **No TLS.** The service speaks plain HTTP and assumes a load balancer or service mesh terminates TLS
  in front of it. That is a legitimate architecture and it means the control is satisfied outside this
  repository or not at all. `COMPLIANCE.md` marks it "Not implemented here" for that reason.
- **No orchestration manifests.** No Kubernetes, no ECS task definition, no Helm chart. The image, its
  signals and its health check are standard enough to wrap in whichever you use, and a manifest nobody
  has run is worse than none.
- **No secret delivery.** `--env-file` is shown because it is the shortest thing that works locally.
  `KEY_ENCRYPTION_KEY` is the key that wraps every other key, and a real deployment should inject it
  from a secret manager. The `KeyProvider` port exists so a KMS or HSM adapter is a new file rather
  than a redesign, and no such adapter is written yet.
- **Existing tenant databases are never migrated.** Only newly provisioned ones get the current DDL. A
  per-tenant migration runner is on the roadmap and does not exist.

## Related pages

- [Getting started](getting-started.md) to run it without Docker.
- [Configuration](configuration.md) for every environment variable.
- [Audit log](audit-log.md#what-this-does-not-do) for what the immutability layers do and do not prove.
- [Operations](operations.md) for the CLI commands and the rotation runbook.
