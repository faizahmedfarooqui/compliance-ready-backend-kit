import { Inject, Injectable, Logger } from "@nestjs/common";
import { ConnectionManager, appendAuditEvent, type AppendAuditEvent } from "@compliance-kit/db";
import { CONNECTION_MANAGER } from "../core/tokens";
import { TenantContextService } from "../tenancy/tenant-context.service";

/**
 * Records audit events on the right chain.
 *
 * WHICH CHAIN, and why there are two. Events about a tenant's users are that tenant's data and go to
 * that tenant's own database, which is what keeps per-tenant export and deletion coherent and is the
 * same reasoning as every other table here. Control-plane events go to the master chain, because at the
 * moment a tenant is provisioned its database does not exist yet, so there is nowhere else to put them.
 *
 * FAIL OPEN, LOUDLY, and this is the decision most worth arguing with.
 *
 * A failed append is logged at error level and the request proceeds. The alternative, failing the
 * request, is defensible and stricter, and it is wrong here: it makes the audit chain a hard dependency
 * for logging in, so an unreachable tenant database would lock every user out of a service that is
 * otherwise healthy, and a provisioning failure after the database was already created would leave an
 * orphaned tenant behind. Turning an evidence-recording problem into an availability outage is a bad
 * trade in both directions.
 *
 * What that costs, stated rather than buried: during an append failure the service performs actions it
 * does not record, so the log has a gap that the hash chain CANNOT reveal. A chain over events 1..n
 * verifies perfectly whether or not an event that was never written should have sat between them.
 * Detecting absence needs something the chain does not provide, which is why every failure is logged at
 * error level and why a deployment that must not lose events should write ahead to a durable queue and
 * drain it into the chain, rather than appending inline as this does.
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    @Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager,
    private readonly tenantCtx: TenantContextService,
  ) {}

  /**
   * Record an event on the CURRENT TENANT's chain.
   *
   * Only callable from a request that resolved a tenant, which every caller of this method is: the
   * routes that emit tenant events all sit behind TenantGuard.
   */
  async tenantEvent(event: AppendAuditEvent): Promise<void> {
    await this.append(this.tenantCtx.db, event, `tenant ${this.tenantCtx.tenant.slug}`);
  }

  /** Record an event on the deployment-wide control-plane chain. */
  async controlPlaneEvent(event: AppendAuditEvent): Promise<void> {
    await this.append(this.cm.master, event, "master");
  }

  private async append(
    client: Parameters<typeof appendAuditEvent>[0],
    event: AppendAuditEvent,
    where: string,
  ): Promise<void> {
    try {
      await appendAuditEvent(client, event);
    } catch (err) {
      /**
       * Everything needed to reconstruct the lost event is in this line, on purpose. It is the only
       * remaining record that the action happened, so a message that said "audit append failed" and
       * nothing else would turn a recoverable gap into an unrecoverable one.
       */
      this.logger.error(
        `AUDIT APPEND FAILED on ${where}, the action proceeded UNRECORDED. ` +
          `action=${event.action} actorType=${event.actorType} actorId=${event.actorId ?? "null"} ` +
          `resource=${event.resourceType ?? "null"}/${event.resourceId ?? "null"} ` +
          `metadata=${JSON.stringify(event.metadata ?? {})}: ` +
          `${err instanceof Error ? err.message : String(err)}`,
        err instanceof Error ? err.stack : undefined,
      );
    }
  }
}
