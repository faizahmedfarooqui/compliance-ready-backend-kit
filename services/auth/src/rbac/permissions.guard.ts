import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { AccessTokenClaims } from "@compliance-kit/common";
import { PERMISSIONS_KEY } from "./permissions.decorator";

/**
 * Enforces the permissions declared with @RequirePermissions. Reads the caller's
 * permissions from the verified JWT claims (set on request.user by JwtAuthGuard),
 * so this guard must run after authentication.
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required =
      this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
    if (required.length === 0) return true;

    const req = context.switchToHttp().getRequest<{ user?: AccessTokenClaims }>();
    if (!req.user) throw new ForbiddenException("No authenticated user");

    const held = new Set(req.user.permissions ?? []);
    if (!required.every((p) => held.has(p))) {
      throw new ForbiddenException("Missing required permission");
    }
    return true;
  }
}
