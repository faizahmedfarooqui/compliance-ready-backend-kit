import { UseGuards, applyDecorators } from "@nestjs/common";
import type { PermissionKey } from "@compliance-kit/common";
import { TenantGuard } from "../tenancy/tenant.guard";
import { AccessTokenGuard } from "../auth/access-token.guard";
import { PermissionsGuard } from "./permissions.guard";
import { RequirePermissions } from "./permissions.decorator";

/**
 * The complete access-control chain for a tenant-scoped route, in the only order that
 * is correct:
 *
 *   1. TenantGuard       resolve x-tenant-id -> this tenant's database
 *   2. AccessTokenGuard  decrypt + verify the nested JWT, AND require that its `tid` claim
 *                        is the tenant just resolved
 *   3. PermissionsGuard  the caller must hold the declared permissions
 *
 * Exposed as one decorator rather than three guards because the order is load-bearing and a
 * chain assembled by hand is a chain someone can assemble wrongly: drop step 1 and there is
 * no database to query and no tenant to bind the token to. Prefer this over @UseGuards for
 * anything tenant-scoped.
 *
 * Usage: `@TenantAuthenticated(PERMISSION_KEYS.usersRead)`
 */
export function TenantAuthenticated(...permissions: PermissionKey[]) {
  return applyDecorators(
    UseGuards(TenantGuard, AccessTokenGuard, PermissionsGuard),
    RequirePermissions(...permissions),
  );
}
