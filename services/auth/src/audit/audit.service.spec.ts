import { describe, expect, it, vi } from "vitest";
import { TenantContextMissingError } from "@compliance-kit/common";
import type { ConnectionManager } from "@compliance-kit/db";
import type { TenantContextService } from "../tenancy/tenant-context.service";
import { AuditService } from "./audit.service";

/**
 * Fail open is the whole contract of this service, so it is asserted rather than documented.
 *
 * The regression these tests exist for: `tenantEvent` read the tenant context as ARGUMENTS to its
 * private `append()`, so the read happened before append's try/catch. Both accessors throw when no
 * tenant was resolved, which meant the one method whose documented job is never to disturb the request
 * path could still throw, and the caller that most needs it not to is PermissionsGuard. A mis-ordered
 * guard chain would have turned an intended 403 into a 400 about a missing tenant header.
 *
 * A comment saying "fails open" is worth nothing here, because the failure only appears on a path
 * nobody exercises by hand. Hence assertions.
 */

/** A tenant context that throws on access, exactly as TenantContextService does off-request. */
function missingContext(): TenantContextService {
  return {
    get db(): never {
      throw new TenantContextMissingError();
    },
    get tenant(): never {
      throw new TenantContextMissingError();
    },
  } as unknown as TenantContextService;
}

/** A context whose database rejects every append, which is the other way an append can fail. */
function contextWithFailingDb(): TenantContextService {
  return {
    db: { $transaction: () => Promise.reject(new Error("ECONNREFUSED")) },
    tenant: { slug: "acme" },
  } as unknown as TenantContextService;
}

function workingContext(calls: string[]): TenantContextService {
  return {
    db: {
      $transaction: (fn: (tx: unknown) => Promise<unknown>) => {
        calls.push("transaction");
        return fn({
          $executeRawUnsafe: () => Promise.resolve(0),
          $queryRawUnsafe: (sql: string) => {
            if (sql.includes("now()")) {
              return Promise.resolve([
                { now_at: new Date("2026-07-31T00:00:00.000Z"), prev_hash: null },
              ]);
            }
            return Promise.resolve([{ seq: 1n }]);
          },
        });
      },
    },
    tenant: { slug: "acme" },
  } as unknown as TenantContextService;
}

const cm = { master: {} } as unknown as ConnectionManager;

describe("AuditService", () => {
  it("records a tenant event when the context and database are healthy", async () => {
    const calls: string[] = [];
    const service = new AuditService(cm, workingContext(calls));
    await expect(
      service.tenantEvent({ action: "auth.login.succeeded", actorType: "user", actorId: "u1" }),
    ).resolves.toBeUndefined();
    expect(calls).toEqual(["transaction"]);
  });

  /**
   * THE REGRESSION. Before the fix this rejected with TenantContextMissingError, so a guard emitting a
   * denial without a resolved tenant reported the wrong error to the caller.
   */
  it("swallows a missing tenant context rather than throwing", async () => {
    const service = new AuditService(cm, missingContext());
    await expect(
      service.tenantEvent({ action: "authz.denied", actorType: "anonymous" }),
    ).resolves.toBeUndefined();
  });

  it("swallows a database failure too, since the reason for failing open does not depend on the cause", async () => {
    const service = new AuditService(cm, contextWithFailingDb());
    await expect(
      service.tenantEvent({ action: "auth.login.failed", actorType: "anonymous" }),
    ).resolves.toBeUndefined();
  });

  /**
   * Failing open silently would be the worse bug, because the chain cannot reveal an event that was
   * never written: a chain over events 1..n verifies whether or not something belonged between them.
   * So the log line is the only remaining record, and it must carry enough to reconstruct the event.
   */
  it("logs enough to reconstruct the lost event, because nothing else will have it", async () => {
    const errors: string[] = [];
    const service = new AuditService(cm, contextWithFailingDb());
    vi.spyOn(
      (service as unknown as { logger: { error: (m: string) => void } }).logger,
      "error",
    ).mockImplementation((m: string) => {
      errors.push(m);
    });

    await service.tenantEvent({
      action: "auth.login.failed",
      actorType: "user",
      actorId: "u1",
      resourceType: "user",
      resourceId: "u1",
      metadata: { email: "a@b.example", reason: "wrong_password" },
    });

    expect(errors).toHaveLength(1);
    const line = errors[0];
    for (const fragment of [
      "UNRECORDED",
      "auth.login.failed",
      "u1",
      "wrong_password",
      "a@b.example",
    ]) {
      expect(line).toContain(fragment);
    }
  });

  it("says which chain the append was meant for, so an operator knows where the gap is", async () => {
    const errors: string[] = [];
    const service = new AuditService(cm, contextWithFailingDb());
    vi.spyOn(
      (service as unknown as { logger: { error: (m: string) => void } }).logger,
      "error",
    ).mockImplementation((m: string) => {
      errors.push(m);
    });
    await service.tenantEvent({ action: "x.y", actorType: "system" });
    expect(errors[0]).toContain("tenant acme");
  });

  // The master chain has no tenant context to be missing, so its only failure mode is the append.
  it("swallows a control-plane append failure", async () => {
    const failingMaster = {
      master: { $transaction: () => Promise.reject(new Error("down")) },
    } as unknown as ConnectionManager;
    const service = new AuditService(failingMaster, missingContext());
    await expect(
      service.controlPlaneEvent({ action: "tenant.provisioned", actorType: "control_plane" }),
    ).resolves.toBeUndefined();
  });
});
