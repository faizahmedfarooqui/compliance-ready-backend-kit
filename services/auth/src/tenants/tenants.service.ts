import { Inject, Injectable } from "@nestjs/common";
import { ConnectionManager } from "@compliance-kit/db";
import type { Tenant } from "@compliance-kit/common";
import { CONNECTION_MANAGER } from "../core/tokens";
import { AuditService } from "../audit/audit.service";
import type { ProvisionTenantDto } from "./dto/provision-tenant.dto";

@Injectable()
export class TenantsService {
  constructor(
    @Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager,
    private readonly audit: AuditService,
  ) {}

  /**
   * Provision a tenant and record it on the control-plane chain.
   *
   * Recorded on the MASTER chain, not the new tenant's. The tenant's own chain exists by the time this
   * returns, so it would work, but putting the record there means the evidence that a tenant was created
   * lives only inside the thing that was created: drop the database and the record of its creation goes
   * with it. The control plane is the durable place for a control-plane action.
   *
   * AFTER provisioning, so a failed provision is never recorded as a completed one. The cost is that a
   * provision which succeeds and then fails to record leaves a tenant with no creation event, which is
   * why that failure is logged loudly. See AuditService for why that is preferred to failing the request
   * and orphaning a database that has already been created.
   *
   * `control_plane` with NO actor id, and the `audit_events_actor_ck` constraint enforces that rather
   * than trusting this code to remember. The credential authenticates the bearer and not a person, so an
   * identifier here would imply an attribution it cannot support. What this row can honestly say is that
   * the control plane was used; answering WHO needs mutual TLS or a signed operator token.
   */
  async provision(dto: ProvisionTenantDto): Promise<Tenant> {
    const tenant = await this.cm.provisionTenant({ slug: dto.slug, name: dto.name });

    await this.audit.controlPlaneEvent({
      action: "tenant.provisioned",
      actorType: "control_plane",
      resourceType: "tenant",
      resourceId: tenant.id,
      metadata: { slug: tenant.slug, databaseName: tenant.databaseName },
    });

    return tenant;
  }
}
