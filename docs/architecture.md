# Architecture

The monorepo layout, which package owns what, and why the boundaries fall where they do.

## Shape

A pnpm workspace with two kinds of member:

```
packages/          shared libraries, published nowhere, consumed by everything
  common/          domain types, the RBAC catalogue, the wire contract, domain errors
  config/          the zod-validated configuration schema and loader
  crypto/          EVERYTHING cryptographic: Argon2id, the token codec, key material, audit hashing
  db/              Prisma clients, the ConnectionManager, operator CLIs, the audit writer
services/
  auth/            the deployable NestJS application
prisma/
  master/          the control-plane schema; migrates normally
  tenant/          the per-tenant schema; rendered to SQL and applied at provisioning
scripts/           smoke test, probes, operational shell scripts
```

Workspace packages resolve each other through their `package.json` `main` and `types`, which point
into `dist/`. That has one consequence worth knowing before it confuses you: **`dist/` is
gitignored, so a fresh clone must `pnpm build` before `pnpm typecheck` will work.** Otherwise every
cross-package import fails with "Cannot find module '@compliance-kit/common'". CI orders build before
typecheck for exactly this reason.

The same fact bites when switching branches. `dist/` holds the *other* branch's API until you rebuild,
and `tsc` then reports confident nonsense about types that no longer exist. **Run `pnpm build` after
any branch switch before believing a type error**, and reload your editor's TypeScript server, which
caches the old declarations.

## Why these package boundaries

### `packages/crypto` owns everything cryptographic

Not a style preference. Both the auth service and the tenant-admin seed script need the Argon2
parameters, and both the service and the operator CLIs need the token codec. Two copies of a work
factor or a token format eventually disagree, and the drift is invisible until someone's password
verifies in one place and not the other.

So: **never import `argon2` or `jose` from any other package.** The package even re-exports the two
JOSE types that leak through its public API (`CryptoKey`, `JWK`) so that no consumer has a reason to
add `jose` as a dependency. A consumer that imports `jose` for a type has also gained the ability to
reach for `SignJWT`, and then there are two places that know the token format.

`packages/crypto` is pure. It holds no keys, reads no database, and has no framework dependency. Keys
are passed in through resolver functions; see [key management](key-management.md).

### `packages/common` is framework-free on purpose

It holds the RBAC catalogue and both wire shapes so that a generated SDK, or any future service, can
import the same definitions rather than re-describing them. Nothing in it imports NestJS.

The RBAC catalogue lives here specifically so the strings used by `@RequirePermissions` on a controller
and the rows seeded into a new tenant's database cannot drift. A permission that is checked but never
seeded is a permanent 403; one that is seeded but never checked is a control nobody enforces. Both are
exactly what an access-control review is meant to surface.

### `packages/db` owns connections, not business logic

The `ConnectionManager` resolves a tenant, routes to its database, provisions new ones, and owns pool
lifetime. The operator CLIs live here too, because `pg` resolves from this package.

## The stack, and two decisions that look wrong

### Prisma 7, not Drizzle

An earlier iteration chose Drizzle for "explicit transaction and connection control". That reason is
obsolete: Prisma 7 removed the Rust query engine and makes driver adapters mandatory, and
`@prisma/adapter-pg`'s `PrismaPg` accepts an existing `pg.Pool`. Since the kit builds the Pool, pool
sizing, lifetime and error handling stay ours. Do not reintroduce Drizzle.

Three Prisma 7 details that cost time to find:

- A datasource `url` in the schema is banned; it lives in `prisma.config.ts`.
- `migrate diff` needs `--config`, because the schema engine takes `--datasource` as a required
  argument.
- Its path flags need the `--flag=value` form. Space-separated silently yields an empty diff and
  exits 0, which looks like "no drift" and is not.

### TypeScript 6, `module: "node20"`, and why not TS 7

TypeScript 7 **cannot be used here.** It ships no programmatic compiler API, and `nest build` and
`nest start --watch` are built on `ts.createProgram`.

TypeScript 6 turns the legacy `moduleResolution: "node"` (node10) into a hard error, which is why the
module setting is `node20`. That change is load-bearing twice: it also lets a CommonJS build statically
`import` the ESM-only `jose`, because TypeScript permits `require(esm)` when the module target is Node
20 or later. **Do not "modernize" it to `node16`**, which reintroduces TS1479 on the jose import.

Node 24 is the target. `.nvmrc` is the single source of truth, and CI reads it through
`actions/setup-node`'s `node-version-file`, so the two cannot drift.

## Inside the auth service

```
services/auth/src/
  main.ts             bootstrap: Fastify adapter, HTTP limits, global prefix, validation pipe
  app.module.ts       module composition and guard registration order
  core/               config provider, ConnectionManager provider, the global filter and interceptor
  common/             ProblemDetailsFilter, ResponseEnvelopeInterceptor, @RawResponse, validation factory
  tenancy/            TenantGuard, TenantContextService          (@Global)
  auth/               login, register, TokenService, AccessTokenGuard, login throttling   (@Global)
  rbac/               PermissionsGuard, @RequirePermissions, @TenantAuthenticated
  audit/              AuditService                                (@Global)
  keys/               KeyRegistryService, the JWKS controller
  ratelimit/          the guard, the Redis sliding-window store, @RateLimit
  users/  tenants/  health/   feature modules
  docs/               the OpenAPI document
```

### Three modules are `@Global()`, and that is deliberate

`TenancyModule`, `AuthModule` and `AuditModule` are global so that `@TenantAuthenticated` resolves its
guards from any feature module. Without that, using one decorator would mean importing two or three
modules in the right combination, which is precisely the footgun the decorator exists to remove.

### Module ordering in `app.module.ts` is not alphabetical

`RateLimitModule` comes before the feature modules so its global guard registers first: an
unauthenticated flood should be rejected by the cheapest available check, not after a database lookup.
`AuditModule` comes before `RbacModule` so the guard's dependency is registered before it is resolved
at boot.

## What is one service today, and what that implies

There is exactly one deployable service. `services/` is plural because the boundaries are drawn for
more than one: `packages/common` carries the wire contract, `packages/crypto` is the only holder of the
token format, and keys are deployment-wide rather than per-service.

The honest limitation of that story is in [key management](key-management.md#the-outer-layer-is-a-shared-secret):
handing a second service the ability to verify tokens today means handing it the symmetric `A256KW`
key, which also lets it read every token. `ECDH-ES` would fix that and is not implemented.

## Related pages

- [Multi-tenancy](multi-tenancy.md) for the database topology, which is the decision hardest to change.
- [Request lifecycle](request-lifecycle.md) for the order things run in.
- [Testing](testing.md) for why the database-facing layers have no unit tests.
