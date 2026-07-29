import { Global, Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { PasswordService } from "./password.service";
import { TokenService } from "./token.service";
import { AccessTokenGuard } from "./access-token.guard";
import { LoginThrottleService } from "./login-throttle.service";

/**
 * No JwtModule and no PassportModule. Access tokens are nested JWTs (signed, then
 * encrypted), which @nestjs/jwt cannot produce (it wraps jsonwebtoken, which is JWS-only)
 * and passport-jwt cannot consume (its token extractor is synchronous and cannot decrypt).
 * TokenService does both directly; AccessTokenGuard is a plain CanActivate.
 *
 * Global for the same reason as TenancyModule: @TenantAuthenticated needs AccessTokenGuard
 * resolvable from any module that applies it. See tenancy.module.ts.
 */
@Global()
@Module({
  controllers: [AuthController],
  providers: [AuthService, PasswordService, TokenService, AccessTokenGuard, LoginThrottleService],
  exports: [TokenService, AccessTokenGuard, PasswordService],
})
export class AuthModule {}
