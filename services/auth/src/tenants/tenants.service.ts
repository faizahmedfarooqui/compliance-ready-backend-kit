import { Inject, Injectable } from "@nestjs/common";
import { ConnectionManager } from "@compliance-kit/db";
import type { Tenant } from "@compliance-kit/common";
import { CONNECTION_MANAGER } from "../core/tokens";
import type { ProvisionTenantDto } from "./dto/provision-tenant.dto";

@Injectable()
export class TenantsService {
  constructor(@Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager) {}

  /**
   * Thin today, but the seam where v0.2 adds the admin authorization check and the audit
   * log entry that provisioning needs before it can be exposed. See the controller.
   */
  provision(dto: ProvisionTenantDto): Promise<Tenant> {
    return this.cm.provisionTenant({ slug: dto.slug, name: dto.name });
  }
}
