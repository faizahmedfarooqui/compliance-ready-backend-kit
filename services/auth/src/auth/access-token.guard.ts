import { type CanActivate, type ExecutionContext, Injectable } from "@nestjs/common";
import {
  CrossTenantTokenError,
  InvalidAccessTokenError,
  TenantContextMissingError,
  type AccessTokenClaims,
  type Tenant,
} from "@compliance-kit/common";
import { TokenService } from "./token.service";

interface AuthenticatedRequest {
  headers: Record<string, string | string[] | undefined>;
  tenant?: Tenant;
  user?: AccessTokenClaims;
}

/**
 * Authenticate the caller from the Authorization header and bind them to the tenant the
 * request is addressed to.
 *
 * Replaces the previous @nestjs/passport + passport-jwt strategy. That had to go: the token
 * is now a nested JWT, so it must be decrypted before its signature can be verified, and
 * passport-jwt reads the token through a SYNCHRONOUS extractor
 * (`var token = self._jwtFromRequest(req)`), which cannot await a decryption. Doing it in a
 * plain guard also drops four dependencies (@nestjs/jwt, @nestjs/passport, passport,
 * passport-jwt) in favour of one with no transitive dependencies.
 *
 * The tenant binding lives here, in the same step as authentication, and fails closed. Both
 * of those are deliberate:
 *
 *  - Same step: a validly signed token for tenant A presented with `x-tenant-id: B`
 *    authenticates a principal who holds no account in B, carrying A's permissions.
 *    Database-per-tenant does not catch it, because the query is routed correctly to B's
 *    database and no data crosses between tenants. Physical isolation answers "whose data
 *    can this connection reach"; it does not answer "who is allowed to ask". Separating the
 *    two checks into two guards would let a future route apply one without the other.
 *  - Fails closed: no resolved tenant is an error, not a pass, so an authenticated route
 *    with no TenantGuard in front of it breaks loudly instead of silently skipping the check.
 *
 * HIPAA 164.312(a)(1) and 164.312(d), PCI-DSS Req 7, SOC 2 CC6.1 and CC6.3.
 */
@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly tokens: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();

    if (!req.tenant) throw new TenantContextMissingError();

    const claims = await this.tokens.verify(bearerToken(req));
    if (claims.tid !== req.tenant.id) throw new CrossTenantTokenError();

    req.user = claims;
    return true;
  }
}

/** Extract a bearer token, rejecting anything that is not exactly one well-formed header. */
function bearerToken(req: AuthenticatedRequest): string {
  const header = req.headers.authorization;
  // A repeated Authorization header arrives as an array. Rather than pick one, refuse:
  // which one a proxy forwards is not something to leave to chance.
  if (typeof header !== "string") throw new InvalidAccessTokenError();

  const [scheme, value, ...rest] = header.split(" ");
  if (rest.length > 0 || scheme?.toLowerCase() !== "bearer" || !value) {
    throw new InvalidAccessTokenError();
  }
  return value;
}
