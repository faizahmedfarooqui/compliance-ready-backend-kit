import { Inject, Injectable, Scope } from "@nestjs/common";
import { REQUEST } from "@nestjs/core";
import { TenantContextMissingError, type Tenant } from "@compliance-kit/common";
import type { TenantDb } from "@compliance-kit/db";

interface RequestWithTenant {
  tenant?: Tenant;
  tenantDb?: TenantDb;
}

/**
 * Request-scoped accessor for the current tenant and its database. The values are
 * placed on the request by TenantGuard; services read them here instead of threading
 * the tenant through every call.
 */
@Injectable({ scope: Scope.REQUEST })
export class TenantContextService {
  constructor(@Inject(REQUEST) private readonly req: RequestWithTenant) {}

  get tenant(): Tenant {
    if (!this.req.tenant) throw new TenantContextMissingError();
    return this.req.tenant;
  }

  get db(): TenantDb {
    if (!this.req.tenantDb) throw new TenantContextMissingError();
    return this.req.tenantDb;
  }
}
