import { Global, Module } from "@nestjs/common";
import { TenantGuard } from "./tenant.guard";
import { TenantContextService } from "./tenant-context.service";

/**
 * Global because @TenantAuthenticated composes guards from here and from AuthModule. If
 * these were module-scoped, every feature module would have to import both modules in the
 * right combination just to use one decorator, and forgetting an import would be a DI error
 * at boot rather than a clean "just apply the decorator". The decorator is meant to make the
 * access-control chain impossible to get wrong; that only holds if its parts are always
 * resolvable.
 */
@Global()
@Module({
  providers: [TenantGuard, TenantContextService],
  exports: [TenantGuard, TenantContextService],
})
export class TenancyModule {}
