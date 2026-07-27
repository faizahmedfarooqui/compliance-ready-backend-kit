import { type CanActivate, type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import { ConnectionManager, type TenantDb } from "@compliance-kit/db";
import { TenantNotFoundError, type Tenant } from "@compliance-kit/common";
import { CONNECTION_MANAGER } from "../core/tokens";

/**
 * The request as this guard needs to see it. Typed rather than `Record<string, any>`, because
 * an `any` here defeats the checker on exactly the values that decide which tenant's database a
 * request reaches. Header values are `string | string[] | undefined`: Fastify hands back an
 * array when a header appears more than once.
 */
interface TenantRoutableRequest {
  headers: Record<string, string | string[] | undefined>;
  tenant?: Tenant;
  tenantDb?: TenantDb;
}

/**
 * Resolves the tenant for the request from the `x-tenant-id` header (id or slug),
 * loads its dedicated database, and attaches both to the request. Runs before auth,
 * so every downstream query is bound to exactly one tenant's database.
 */
@Injectable()
export class TenantGuard implements CanActivate {
  constructor(@Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<TenantRoutableRequest>();

    const header = tenantHeader(req);
    if (!header) throw new TenantNotFoundError("(missing x-tenant-id header)");

    const tenant = await this.cm.resolveTenant(header);
    req.tenant = tenant;
    req.tenantDb = this.cm.getTenantDb(tenant);
    return true;
  }
}

/**
 * Read the tenant header, accepting exactly one well-formed value.
 *
 * A repeated header arrives as an array. Refuse rather than pick one: which value a proxy
 * forwards first is not something to leave to chance when it selects the database the request
 * will read. Previously this cast the value to `string` regardless, so a repeated header became
 * the string form of an array and simply failed to resolve, which is the right outcome by luck
 * rather than by decision.
 */
function tenantHeader(req: TenantRoutableRequest): string | undefined {
  const value = req.headers["x-tenant-id"] ?? req.headers["x-tenant"];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
