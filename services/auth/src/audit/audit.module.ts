import { Global, Module } from "@nestjs/common";
import { AuditService } from "./audit.service";

/**
 * Global for the same reason as TenancyModule and RateLimitModule: audit recording is cross-cutting,
 * and a feature module should not have to remember an import to be audited. Coverage that depends on
 * remembering an import is coverage with holes, and a missing audit event is invisible.
 */
@Global()
@Module({ providers: [AuditService], exports: [AuditService] })
export class AuditModule {}
