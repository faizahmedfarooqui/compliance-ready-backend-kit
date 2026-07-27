import { type CanActivate, type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import { ConnectionManager } from "@compliance-kit/db";
import { TenantNotFoundError } from "@compliance-kit/common";
import { CONNECTION_MANAGER } from "../core/tokens";

/**
 * Resolves the tenant for the request from the `x-tenant-id` header (id or slug),
 * loads its dedicated database, and attaches both to the request. Runs before auth,
 * so every downstream query is bound to exactly one tenant's database.
 */
@Injectable()
export class TenantGuard implements CanActivate {
  constructor(@Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Record<string, any>>();
    const header = (req.headers["x-tenant-id"] ?? req.headers["x-tenant"]) as string | undefined;
    if (!header) throw new TenantNotFoundError("(missing x-tenant-id header)");

    const tenant = await this.cm.resolveTenant(header);
    req.tenant = tenant;
    req.tenantDb = this.cm.getTenantDb(tenant);
    return true;
  }
}
