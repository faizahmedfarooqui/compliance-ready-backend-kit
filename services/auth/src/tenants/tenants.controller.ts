import { Body, Controller, Post } from "@nestjs/common";
import type { Tenant } from "@compliance-kit/common";
import { ProvisionTenantDto } from "./dto/provision-tenant.dto";
import { TenantsService } from "./tenants.service";

/**
 * Control-plane endpoint: provisions a new tenant, its dedicated database, and that
 * database's RBAC catalogue.
 *
 * It creates no users. The tenant's first administrator is seeded separately, by
 * `pnpm db:seed:admin`, so that no credential ever travels in this request body and
 * granting a human administrative access is its own auditable step.
 *
 * v0.1 NOTE: intentionally unauthenticated for local bootstrap. It creates databases,
 * which makes it the most privileged route in the kit. A later milestone gates it behind
 * an admin credential and writes to the audit log. Do NOT expose it publicly as-is;
 * see the roadmap in README.md.
 */
@Controller("tenants")
export class TenantsController {
  constructor(private readonly tenants: TenantsService) {}

  @Post()
  provision(@Body() dto: ProvisionTenantDto): Promise<Tenant> {
    return this.tenants.provision(dto);
  }
}
