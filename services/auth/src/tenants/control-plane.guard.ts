import { timingSafeEqual } from "node:crypto";
import { CanActivate, ExecutionContext, Inject, Injectable, Logger } from "@nestjs/common";
import type { FastifyRequest } from "fastify";
import { ControlPlaneUnauthorizedError } from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import { CONFIG } from "../core/tokens";

/**
 * Guards the control plane: the routes that act on the deployment rather than inside a tenant.
 *
 * Why this cannot be the normal access-token guard. Provisioning creates a tenant, so at the moment
 * of the call there is no tenant to be a member of and no user to hold a role. Every credential the
 * data plane uses is scoped to a tenant that does not exist yet, which is why the control plane needs
 * a credential of its own rather than a cleverer use of the existing one.
 *
 * The credential is a shared secret, with the limitations spelled out on `controlPlaneApiKey` in
 * @compliance-kit/config. The important one for an auditor: this authenticates the BEARER, not a
 * person, so the audit trail can record that the control plane was used but not by whom.
 */
@Injectable()
export class ControlPlaneGuard implements CanActivate {
  private readonly logger = new Logger(ControlPlaneGuard.name);
  private readonly expected: Buffer;

  constructor(@Inject(CONFIG) config: AppConfig) {
    // Decoded once at construction rather than per request. See `matches` for the comparison.
    this.expected = Buffer.from(config.controlPlaneApiKey, "utf8");
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const presented = bearer(request.headers.authorization);

    // One error for a missing key and a wrong one. Distinguishing them tells a prober whether the
    // route is protected at all, and whether their header format was accepted, which is two free bits
    // of information about a credential they are trying to guess.
    if (!presented || !this.matches(presented)) {
      this.logger.warn(
        `Rejected control-plane request to ${request.method} ${request.url} from ${request.ip}`,
      );
      throw new ControlPlaneUnauthorizedError();
    }
    return true;
  }

  /**
   * Constant-time comparison of the credential.
   *
   * `timingSafeEqual` THROWS when its two buffers differ in length, so a wrong-length credential must
   * be handled before it is called or it becomes a 500 instead of a 401.
   *
   * An early length check is the right way to do that, because THE LENGTH IS NOT A SECRET. The config
   * schema fixes the credential at 43 base64url characters and `.env.example` publishes that, so
   * returning early on a mismatch tells an attacker only what the documentation already does. What must
   * be constant-time is the comparison of two values of the RIGHT length, since that is where guessing
   * the content would otherwise leak a prefix at a time.
   *
   * This used to digest both sides with SHA-256 to normalise the length, on the theory that the length
   * needed hiding. It did not, and the digest bought nothing: 256 bits of randomness is not
   * brute-forcible whatever the hash speed, and nothing was stored to attack offline. It also drew a
   * CodeQL `js/insufficient-password-hash` alert, which is wrong about the threat here but right that a
   * bare SHA-256 next to a credential deserves an explanation. Removing it is simpler than explaining
   * it, and Argon2 would have been the genuinely bad fix: a deliberate ~100ms of CPU on every
   * control-plane request, which is the amplifier this route is rate limited to avoid.
   */
  private matches(presented: string): boolean {
    const candidate = Buffer.from(presented, "utf8");
    if (candidate.length !== this.expected.length) return false;
    return timingSafeEqual(candidate, this.expected);
  }
}

/**
 * Pull the credential out of an `Authorization: Bearer <key>` header.
 *
 * The scheme name is matched case-insensitively because RFC 9110 §11.1 defines it as a case-
 * insensitive token, so a client sending "bearer" is correct and must not be rejected for it.
 *
 * An array-valued header is refused rather than joined. Fastify hands back an array when a header
 * appears twice, and picking one of them would let a caller send a rejected key alongside an accepted
 * one and have the pair treated as valid depending on which element was read first.
 */
function bearer(header: string | string[] | undefined): string | undefined {
  if (typeof header !== "string") return undefined;
  const match = /^bearer\s+(\S+)$/i.exec(header.trim());
  return match?.[1];
}
