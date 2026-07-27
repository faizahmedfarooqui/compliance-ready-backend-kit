import { SetMetadata } from "@nestjs/common";
import type { PermissionKey } from "@compliance-kit/common";

export const PERMISSIONS_KEY = "required_permissions";

/**
 * Declare the permission keys a route requires, e.g.
 * `@RequirePermissions(PERMISSION_KEYS.usersRead)`.
 *
 * Typed to PermissionKey rather than string on purpose: a route that requires a
 * permission which is never seeded into tenant databases is a permanent 403, and that
 * is much easier to catch at compile time than in an access review.
 */
export const RequirePermissions = (...permissions: PermissionKey[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
