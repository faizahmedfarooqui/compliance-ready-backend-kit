import { Body, Controller, Post, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import type { Tenant } from "@compliance-kit/common";
import { ApiCommonErrors, ApiEnvelope, ApiProblem } from "../docs/api-envelope.decorator";
import { TenantSchema } from "../docs/schemas";
import { RateLimit } from "../ratelimit/rate-limit.decorator";
import { ControlPlaneGuard } from "./control-plane.guard";
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
 * REQUIRES A CONTROL-PLANE CREDENTIAL. Until this landed the route was unauthenticated, with a comment
 * saying it was "intentionally unauthenticated for local bootstrap" and "do NOT expose it publicly
 * as-is". That is not a control: nothing enforced it, nothing detected the mistake, and it was the most
 * privileged route in the kit. Anyone who could reach the port could call it in a loop until the
 * cluster ran out of connections or disk.
 *
 * The credential authenticates the bearer rather than a person, so the guard can record that the
 * control plane was used but not by whom. See `controlPlaneApiKey` in @compliance-kit/config for why
 * that is a deliberate stepping stone rather than a finished design.
 */
@ApiTags("tenants")
@ApiBearerAuth("controlPlane")
@Controller("tenants")
@UseGuards(ControlPlaneGuard)
export class TenantsController {
  constructor(private readonly tenants: TenantsService) {}

  /**
   * Rate limited more tightly than anything else, because the unit of work is enormous: one call
   * creates a database, applies a schema to it, and seeds a catalogue. An attacker holding a leaked
   * credential is bounded to thirty database creations an hour rather than to however fast they can
   * send requests.
   *
   * Thirty rather than five, and the reason is worth recording because it is a real property of the
   * design rather than a preference. RATE LIMITING RUNS BEFORE AUTHENTICATION: the limiter is a global
   * guard and ControlPlaneGuard is a route guard, and Nest runs global guards first. That ordering is
   * correct, since the whole point is to bound floods from callers who have no credential at all. It
   * also means REJECTED calls spend budget. At five per hour, three failed attempts left two, which is
   * not enough for an operator who fumbles a paste, and it was not enough for this kit's own smoke test
   * either. A limit that its own test suite cannot live under is a limit that gets raised in a hurry
   * during an incident, so it is set to a workable number now, with the reasoning attached.
   */
  @Post()
  @RateLimit({ limit: 30, windowMs: 3_600_000 })
  @ApiOperation({
    summary: "Provision a tenant, with its own database",
    description:
      "CONTROL PLANE. Creates the tenant registry row, a dedicated Postgres database, its schema, and " +
      "its RBAC catalogue. Requires the control-plane credential, not a user access token: at the " +
      "moment of the call there is no tenant to be a member of and no user to hold a role.\n\n" +
      "Creates NO users. The first administrator is seeded separately with `pnpm db:seed:admin`, so no " +
      "credential travels in this request body and granting a human administrative access stays a " +
      "distinct, separately auditable step.\n\n" +
      "Limited to 30 per hour. Rate limiting runs before authentication, so rejected calls also spend " +
      "budget.",
  })
  @ApiEnvelope(TenantSchema, { status: 201, description: "Tenant provisioned and active." })
  @ApiProblem(
    401,
    "Missing, malformed, or wrong control-plane credential. One response for all three.",
    "CONTROL_PLANE_UNAUTHORIZED",
  )
  @ApiProblem(409, "A tenant with that slug already exists.", "TENANT_ALREADY_EXISTS")
  @ApiCommonErrors()
  provision(@Body() dto: ProvisionTenantDto): Promise<Tenant> {
    return this.tenants.provision(dto);
  }
}
