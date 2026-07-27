import { describe, expect, it } from "vitest";
import { ForbiddenException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import type { Reflector } from "@nestjs/core";
import type { AccessTokenClaims } from "@compliance-kit/common";
import { PermissionsGuard } from "./permissions.guard";

/**
 * This guard is the last gate before a handler runs, so its default matters: a route whose
 * required permissions cannot be read must not be treated as public.
 */

function contextWith(user: AccessTokenClaims | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ user }) }),
    // A distinguishable handler reference is all the reflector mock needs.
    getHandler: () =>
      function handler() {
        return undefined;
      },
    getClass: () => class Controller {},
  } as unknown as ExecutionContext;
}

function reflectorReturning(required: string[] | undefined): Reflector {
  return { getAllAndOverride: () => required } as unknown as Reflector;
}

const claims = (permissions: string[]): AccessTokenClaims => ({
  sub: "11111111-1111-4111-8111-111111111111",
  tid: "22222222-2222-4222-8222-222222222222",
  roles: ["tenant-admin"],
  permissions,
});

describe("PermissionsGuard", () => {
  it("allows a caller holding the required permission", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]));
    expect(guard.canActivate(contextWith(claims(["users:read"])))).toBe(true);
  });

  it("allows a caller holding more than the required permissions", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]));
    expect(guard.canActivate(contextWith(claims(["users:read", "users:write"])))).toBe(true);
  });

  it("requires ALL declared permissions, not any of them", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read", "roles:manage"]));
    expect(() => guard.canActivate(contextWith(claims(["users:read"])))).toThrow(
      ForbiddenException,
    );
  });

  it("denies a caller holding none of them", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]));
    expect(() => guard.canActivate(contextWith(claims([])))).toThrow(ForbiddenException);
  });

  // A registered user with no roles holds no permissions, which is the normal denial path.
  it("denies when the token carries an empty permission list", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]));
    expect(() => guard.canActivate(contextWith(claims([])))).toThrow(/Missing required permission/);
  });

  // Fails closed: no authenticated principal is a denial, not a pass.
  it("denies when there is no authenticated user on the request", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]));
    expect(() => guard.canActivate(contextWith(undefined))).toThrow(/No authenticated user/);
  });

  // A route that declares nothing is intentionally open at this layer; TenantGuard and
  // AccessTokenGuard have already run by the time this is reached.
  it("allows a route that declares no permissions", () => {
    const guard = new PermissionsGuard(reflectorReturning([]));
    expect(guard.canActivate(contextWith(claims([])))).toBe(true);
  });

  it("treats missing metadata as no requirement rather than throwing", () => {
    const guard = new PermissionsGuard(reflectorReturning(undefined));
    expect(guard.canActivate(contextWith(claims([])))).toBe(true);
  });

  // Permission keys are exact strings. A prefix must not satisfy a longer requirement.
  it("does not match a permission by prefix", () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]));
    expect(() => guard.canActivate(contextWith(claims(["users"])))).toThrow(ForbiddenException);
  });
});
