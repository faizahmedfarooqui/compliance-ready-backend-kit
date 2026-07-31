import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { AccessTokenClaims } from "@compliance-kit/common";
import type { FastifyRequest } from "fastify";
import { AuditService } from "../audit/audit.service";
import { PERMISSIONS_KEY } from "./permissions.decorator";

/**
 * Enforces the permissions declared with @RequirePermissions. Reads the caller's
 * permissions from the verified JWT claims (set on request.user by AccessTokenGuard),
 * so this guard must run after authentication.
 *
 * NOW ASYNC, because a denial is recorded before it is thrown.
 *
 * A refused authorization attempt is the event an access review actually asks for: not who has which
 * role, which the database already says, but who TRIED to do something they were not entitled to. It is
 * also the signal that separates a misconfigured integration from someone probing, and neither shows up
 * anywhere else, since the response deliberately says only "Missing required permission".
 *
 * The cost is that this guard, which sits in the request path of every protected route, now awaits a
 * database write on the denial path. That is acceptable precisely because it is the DENIAL path: an
 * allowed request pays nothing, and a caller generating enough denials for the write to matter is the
 * caller this record exists to document. AuditService fails open, so an unwritable chain slows the
 * rejection rather than turning it into a 500.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly audit: AuditService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const required =
      this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    if (required.length === 0) return true;

    const req = context.switchToHttp().getRequest<FastifyRequest & { user?: AccessTokenClaims }>();

    if (!req.user) {
      // Reached when this guard runs without authentication in front of it, which is a wiring mistake
      // rather than a caller's. Recorded as `anonymous` because there is genuinely no actor to name.
      await this.deny(req, required, [], "no_authenticated_user", null);
      throw new ForbiddenException("No authenticated user");
    }

    const held = new Set(req.user.permissions ?? []);
    const missing = required.filter((p) => !held.has(p));
    if (missing.length > 0) {
      await this.deny(req, required, missing, "missing_permission", req.user.sub);
      throw new ForbiddenException("Missing required permission");
    }
    return true;
  }

  /**
   * Records what was required and what was missing, not just that a denial happened.
   *
   * Both, because they answer different questions. `required` says what the route demands, which is what
   * an integrator needs to fix their grant. `missing` says which of those the caller lacked, which is
   * what tells an investigator whether someone was one permission short of a legitimate action or
   * nowhere near it.
   */
  private async deny(
    req: FastifyRequest,
    required: string[],
    missing: string[],
    reason: string,
    actorId: string | null,
  ): Promise<void> {
    await this.audit.tenantEvent({
      action: "authz.denied",
      actorType: actorId === null ? "anonymous" : "user",
      actorId,
      sourceIp: req.ip,
      metadata: {
        reason,
        method: req.method,
        // The route PATTERN, not the resolved URL, so these group in a query and a path parameter does
        // not fragment them into thousands of distinct values.
        route: req.routeOptions?.url ?? req.url.split("?")[0],
        required: required.join(","),
        missing: missing.join(","),
      },
    });
  }
}
