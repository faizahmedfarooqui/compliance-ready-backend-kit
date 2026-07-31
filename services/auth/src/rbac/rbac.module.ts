import { Global, Module } from "@nestjs/common";
import { PermissionsGuard } from "./permissions.guard";

/**
 * Registers PermissionsGuard so its dependencies are resolved at BOOT rather than at the first request
 * to a protected route.
 *
 * It worked without this. Nest instantiates a class passed to `@UseGuards` on demand using the
 * enclosing module's injector, and both of the guard's dependencies are globally available: `Reflector`
 * always, and `AuditService` because AuditModule is `@Global()`. Verified rather than assumed:
 * `GET /users` as a role-less caller returns 403 with an `authz.denied` event recorded and no
 * resolution error anywhere in the log.
 *
 * The reason to register it anyway is WHEN a mistake would surface. Lazily instantiated, a broken
 * dependency graph produces a healthy boot, a passing health check, and a failure on the first request
 * that hits a permission check, which in this service is a 403 path that gets exercised less often than
 * the happy one. Registered, Nest resolves it during bootstrap and the process refuses to start
 * instead. Same reasoning as the other two guards in the chain, which are registered in TenancyModule
 * and AuthModule.
 *
 * `@Global()` because @TenantAuthenticated applies this guard from any feature module, so requiring an
 * import would be the footgun that decorator exists to remove.
 */
@Global()
@Module({ providers: [PermissionsGuard], exports: [PermissionsGuard] })
export class RbacModule {}
