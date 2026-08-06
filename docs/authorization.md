# Authorization

RBAC: the permission catalogue, how a route is protected, and how a denial becomes evidence.

## The model

Three tables in every tenant database, plus two join tables:

```
users ──< user_roles >── roles ──< role_permissions >── permissions
```

Permissions are the unit that gets checked. Roles are a bundle of permissions. A user holds roles, and
the union of their permissions is baked into the access token at login.

Each tenant database gets its own catalogue at provisioning, seeded from
`DEFAULT_PERMISSIONS` in `packages/common`:

| Key | Description |
| --- | --- |
| `users:read` | List and view users in this tenant |
| `users:write` | Create, modify, and disable users in this tenant |
| `roles:manage` | Create roles and change their permission grants |

Plus one role, `tenant-admin`, holding all three and granted to the tenant's seeded first
administrator.

**That is a starting point for least privilege, not a finished role model.** Three permissions and one
role is what a kit can honestly ship; a real deployment defines its own.

## Why the catalogue is declared in code

`PERMISSION_KEYS` in `packages/common/src/index.ts` is the single source for permission strings, and it
is deliberately framework-free so that both the controller decorators and the provisioning seed import
the same constants.

The failure this prevents is drift between the two:

- A permission **checked but never seeded** is a permanent 403 that looks like a bug in the caller.
- A permission **seeded but never checked** is a control nobody enforces, which reads as an
  access-control capability on paper and does nothing.

Both are precisely what an access-control review under HIPAA 164.312(a)(1), PCI Req 7 or SOC 2 CC6.3 is
meant to surface, which is a good reason not to let them happen quietly.

## Protecting a route

Use `@TenantAuthenticated`, which applies the whole chain in the only correct order plus the permission
requirement:

```ts
import { PERMISSION_KEYS } from "@compliance-kit/common";

@Controller("users")
export class UsersController {
  @Get()
  @TenantAuthenticated(PERMISSION_KEYS.usersRead)
  async list(): Promise<UserSummary[]> {
    return this.users.list();
  }
}
```

That expands to:

```ts
UseGuards(TenantGuard, AccessTokenGuard, PermissionsGuard)
RequirePermissions(...permissions)
```

**Prefer it over assembling `@UseGuards` by hand.** The order is load-bearing: drop `TenantGuard` and
there is no database to query and no tenant to bind the token to. A chain assembled by hand is a chain
someone can assemble wrongly, and the decorator exists to remove that option. It works from any feature
module without extra imports because `TenancyModule`, `AuthModule` and `AuditModule` are `@Global()`.

Multiple permissions are **all** required:

```ts
@TenantAuthenticated(PERMISSION_KEYS.usersWrite, PERMISSION_KEYS.rolesManage)
```

## Adding a permission

1. Add the key to `PERMISSION_KEYS` in `packages/common/src/index.ts`.
2. Add a `PermissionDefinition` to `DEFAULT_PERMISSIONS` with a description, so new tenants seed it.
3. Use it in a `@TenantAuthenticated(...)` on the routes it governs.
4. Add the row to the control mapping in [COMPLIANCE.md](../COMPLIANCE.md) if it represents a new
   capability rather than a finer slice of an existing one.

Step 2 only affects **new** tenants. Existing tenant databases are not migrated, which is a known
limitation; see [multi-tenancy](multi-tenancy.md#known-limitations). Until a per-tenant migration runner
exists, adding a permission to a live deployment means granting it to existing tenants yourself.

## How a denial is handled

`PermissionsGuard` reads the required permissions from the handler and class metadata, compares them
against `request.user.permissions` from the verified token, and throws `ForbiddenException` when any are
missing. The response says only "Missing required permission".

Before throwing, it **records the denial** to the tenant's audit chain:

```
action:     authz.denied
actorType:  user (or anonymous, when there is no authenticated caller at all)
actorId:    the user id, or null
sourceIp:   request.ip
metadata:   reason, method, route, required, missing
```

### Why record it at all

A refused authorization attempt is the event an access review actually asks for. Not "who has which
role", which the database already answers, but **who tried to do something they were not entitled to**.
It is also the only signal that distinguishes a misconfigured integration from someone probing, and it
appears nowhere else, because the response deliberately reveals nothing.

### Why both `required` and `missing`

They answer different questions. `required` is what the route demands, which is what an integrator needs
in order to fix their grant. `missing` is which of those the caller lacked, which tells an investigator
whether someone was one permission short of a legitimate action or nowhere near it.

The route **pattern** is recorded rather than the resolved URL, so events group in a query instead of a
path parameter fragmenting them into thousands of distinct values.

### The cost, and why it is acceptable

This guard sits in the request path of every protected route and now awaits a database write on the
denial path. That is fine precisely because it is the *denial* path: an allowed request pays nothing,
and a caller generating enough denials for the write to matter is exactly the caller this record exists
to document. `AuditService` fails open, so an unwritable chain slows the rejection rather than turning it
into a 500.

### The `anonymous` case is a wiring bug, recorded as one

If `PermissionsGuard` runs with no authenticated user on the request, that means authentication was not
in front of it: a wiring mistake, not a caller's fault. It records the denial with actor type
`anonymous`, because there is genuinely no actor to name, and the database's
`audit_events_actor_ck` constraint requires that an `anonymous` event carry no actor id.

## Reading the tenant's data

Inject `TenantContextService`. It is request-scoped and exposes the resolved tenant and a Prisma client
already pointed at that tenant's database:

```ts
constructor(private readonly ctx: TenantContextService) {}

async list() {
  return this.ctx.db.user.findMany({ select: { id: true, email: true } });
}
```

Both getters throw `TenantContextMissingError` if no tenant was resolved, so a service used outside a
tenant-scoped route fails loudly rather than reading from nowhere.

## Known limitations

- **Permissions are baked into the token at login**, so a revoked grant remains effective until the
  token expires, up to 15 minutes by default.
- **No role management API.** Roles and grants are seeded at provisioning; changing them means writing
  to the tenant database. `roles:manage` exists as a permission and there is no route behind it yet.
- **No hierarchical roles, no permission wildcards, no resource-scoped permissions.** A permission
  applies to a route, not to a specific record.
- **Three permissions is a starting point.** Anything real needs more.

## Control mapping

RBAC maps to HIPAA 164.312(a)(1), 164.312(a)(2)(i) and 164.308(a)(4), PCI-DSS Req 7, and SOC 2 CC6.3,
marked Implemented. The denial record contributes to the audit logging row, HIPAA 164.312(b) and
164.308(a)(1)(ii)(D), PCI Req 10, SOC 2 CC7.2. See [COMPLIANCE.md](../COMPLIANCE.md).
