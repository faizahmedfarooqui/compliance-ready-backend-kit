import { describe, expect, it, vi } from "vitest";
import { ForbiddenException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";
import type { Reflector } from "@nestjs/core";
import type { AccessTokenClaims } from "@compliance-kit/common";
import type { AuditService } from "../audit/audit.service";
import { PermissionsGuard } from "./permissions.guard";

/**
 * This guard is the last gate before a handler runs, so its default matters: a route whose
 * required permissions cannot be read must not be treated as public.
 */

/** Captures the events the guard records, so the denial path can be asserted rather than assumed. */
function auditSpy() {
  const events: { action: string; metadata?: Record<string, string> }[] = [];
  const tenantEvent = vi.fn((e: { action: string; metadata?: Record<string, string> }) => {
    events.push(e);
    return Promise.resolve();
  });
  return { audit: { tenantEvent } as unknown as AuditService, events };
}

function contextWith(user: AccessTokenClaims | undefined): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        user,
        ip: "203.0.113.7",
        method: "GET",
        url: "/api/users?page=2",
        routeOptions: { url: "/api/users" },
      }),
    }),
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
  it("allows a caller holding the required permission", async () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]), auditSpy().audit);
    await expect(guard.canActivate(contextWith(claims(["users:read"])))).resolves.toBe(true);
  });

  it("allows a caller holding more than the required permissions", async () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]), auditSpy().audit);
    await expect(
      guard.canActivate(contextWith(claims(["users:read", "users:write"]))),
    ).resolves.toBe(true);
  });

  it("requires ALL declared permissions, not any of them", async () => {
    const guard = new PermissionsGuard(
      reflectorReturning(["users:read", "roles:manage"]),
      auditSpy().audit,
    );
    await expect(guard.canActivate(contextWith(claims(["users:read"])))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it("denies a caller holding none of them", async () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]), auditSpy().audit);
    await expect(guard.canActivate(contextWith(claims([])))).rejects.toThrow(ForbiddenException);
  });

  // A registered user with no roles holds no permissions, which is the normal denial path.
  it("denies when the token carries an empty permission list", async () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]), auditSpy().audit);
    await expect(guard.canActivate(contextWith(claims([])))).rejects.toThrow(
      /Missing required permission/,
    );
  });

  // Fails closed: no authenticated principal is a denial, not a pass.
  it("denies when there is no authenticated user on the request", async () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]), auditSpy().audit);
    await expect(guard.canActivate(contextWith(undefined))).rejects.toThrow(
      /No authenticated user/,
    );
  });

  // A route that declares nothing is intentionally open at this layer; TenantGuard and
  // AccessTokenGuard have already run by the time this is reached.
  it("allows a route that declares no permissions", async () => {
    const guard = new PermissionsGuard(reflectorReturning([]), auditSpy().audit);
    await expect(guard.canActivate(contextWith(claims([])))).resolves.toBe(true);
  });

  it("treats missing metadata as no requirement rather than throwing", async () => {
    const guard = new PermissionsGuard(reflectorReturning(undefined), auditSpy().audit);
    await expect(guard.canActivate(contextWith(claims([])))).resolves.toBe(true);
  });

  // Permission keys are exact strings. A prefix must not satisfy a longer requirement.
  it("does not match a permission by prefix", async () => {
    const guard = new PermissionsGuard(reflectorReturning(["users:read"]), auditSpy().audit);
    await expect(guard.canActivate(contextWith(claims(["users"])))).rejects.toThrow(
      ForbiddenException,
    );
  });

  /**
   * The denial event is the point of making this guard async, so it is asserted rather than assumed.
   *
   * A refused authorization attempt is what an access review actually asks for: not who holds which role,
   * which the database already says, but who TRIED something they were not entitled to. The response says
   * only "Missing required permission", so if this row is not written the attempt leaves no trace at all.
   */
  describe("records the denial", () => {
    it("emits authz.denied when a permission is missing", async () => {
      const spy = auditSpy();
      const guard = new PermissionsGuard(reflectorReturning(["users:read"]), spy.audit);
      await expect(guard.canActivate(contextWith(claims([])))).rejects.toThrow(ForbiddenException);
      expect(spy.events.map((e) => e.action)).toEqual(["authz.denied"]);
    });

    // Both, because they answer different questions: `required` is what the integrator must grant,
    // `missing` is how far short the caller fell, which is what separates a near miss from probing.
    it("records what was required AND what was missing", async () => {
      const spy = auditSpy();
      const guard = new PermissionsGuard(
        reflectorReturning(["users:read", "users:write"]),
        spy.audit,
      );
      await expect(guard.canActivate(contextWith(claims(["users:read"])))).rejects.toThrow();
      expect(spy.events[0].metadata?.required).toBe("users:read,users:write");
      expect(spy.events[0].metadata?.missing).toBe("users:write");
    });

    // The route PATTERN, so denials group in a query instead of fragmenting across path parameters and
    // query strings. `/api/users?page=2` must not become its own bucket.
    it("records the route pattern, not the resolved URL", async () => {
      const spy = auditSpy();
      const guard = new PermissionsGuard(reflectorReturning(["users:read"]), spy.audit);
      await expect(guard.canActivate(contextWith(claims([])))).rejects.toThrow();
      expect(spy.events[0].metadata?.route).toBe("/api/users");
    });

    it("distinguishes a missing permission from a missing authenticated user", async () => {
      const spy = auditSpy();
      const guard = new PermissionsGuard(reflectorReturning(["users:read"]), spy.audit);
      await expect(guard.canActivate(contextWith(undefined))).rejects.toThrow();
      expect(spy.events[0].metadata?.reason).toBe("no_authenticated_user");
    });

    // An allowed request must not pay for the audit write, and must not clutter the log with
    // non-events. Only refusals are recorded.
    it("records nothing when the caller is allowed", async () => {
      const spy = auditSpy();
      const guard = new PermissionsGuard(reflectorReturning(["users:read"]), spy.audit);
      await expect(guard.canActivate(contextWith(claims(["users:read"])))).resolves.toBe(true);
      expect(spy.events).toEqual([]);
    });

    it("records nothing when the route declares no permissions", async () => {
      const spy = auditSpy();
      const guard = new PermissionsGuard(reflectorReturning([]), spy.audit);
      await expect(guard.canActivate(contextWith(claims([])))).resolves.toBe(true);
      expect(spy.events).toEqual([]);
    });
  });
});
