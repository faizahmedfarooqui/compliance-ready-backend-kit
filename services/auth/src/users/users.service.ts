import { Injectable } from "@nestjs/common";
import { TenantContextService } from "../tenancy/tenant-context.service";

@Injectable()
export class UsersService {
  constructor(private readonly tenantCtx: TenantContextService) {}

  /**
   * List users in the CURRENT tenant's database. Note the absence of a tenant predicate:
   * there is nothing to filter by, because this connection can only reach one tenant's
   * database. The isolation is physical, so forgetting a WHERE clause cannot leak across
   * tenants. `select` is explicit so a column added later (a password hash, an MFA
   * secret) is not exposed by default.
   */
  list() {
    return this.tenantCtx.db.user.findMany({
      select: { id: true, email: true, status: true, createdAt: true },
      orderBy: { createdAt: "asc" },
    });
  }
}
