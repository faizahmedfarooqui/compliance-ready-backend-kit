import { createHash, timingSafeEqual } from "node:crypto";
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
    // Digested once at construction. See `matches` for why both sides are hashed.
    this.expected = sha256(config.controlPlaneApiKey);
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
   * Constant-time comparison, via a digest of both sides.
   *
   * `timingSafeEqual` THROWS when the two buffers differ in length, so calling it on raw inputs both
   * crashes on a wrong-length key and leaks the expected length through the difference between a 500
   * and a 401. Hashing first makes both operands exactly 32 bytes, so the comparison is always
   * well-formed and its duration reveals nothing about the length or content of what was presented.
   *
   * The digest is not there to protect the key, which is high-entropy and already secret. It is there
   * to normalise the length.
   */
  private matches(presented: string): boolean {
    return timingSafeEqual(sha256(presented), this.expected);
  }
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
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
