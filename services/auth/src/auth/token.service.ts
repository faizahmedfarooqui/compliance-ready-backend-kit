import { Inject, Injectable } from "@nestjs/common";
import {
  TokenVerificationError,
  issueNestedToken,
  verifyNestedToken,
  type TokenPolicy,
} from "@compliance-kit/crypto";
import type { AppConfig } from "@compliance-kit/config";
import { InvalidAccessTokenError, type AccessTokenClaims } from "@compliance-kit/common";
import { CONFIG } from "../core/tokens";
import { KeyRegistryService } from "../keys/key-registry.service";

/**
 * Issues and verifies access tokens. The nested-JWT mechanics live in @compliance-kit/crypto and the
 * key lifecycle in KeyRegistryService; this binds them to the validated config and to the kit's
 * claim shape, and it is the only place either operation happens.
 */
@Injectable()
export class TokenService {
  private readonly policy: TokenPolicy;

  constructor(
    @Inject(CONFIG) config: AppConfig,
    private readonly keys: KeyRegistryService,
  ) {
    this.policy = {
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      ttlSeconds: config.jwtAccessTtlSeconds,
      clockToleranceSeconds: config.jwtClockToleranceSeconds,
    };
  }

  /** Sign and encrypt with whichever keys are currently active. */
  issue(claims: AccessTokenClaims): Promise<string> {
    return issueNestedToken({ ...claims }, this.keys.activeMaterial(), this.policy);
  }

  /**
   * Verify a token and return its claims, or throw InvalidAccessTokenError.
   *
   * Every failure mode collapses to one error with one message. Distinguishing "expired" from "bad
   * signature" from "unknown kid" in the response would tell an attacker which part of a forged
   * token to fix next.
   *
   * On failure this retries once after asking the registry to refresh. That covers the legitimate
   * case where an operator has just rotated or revoked a key and this instance's snapshot predates
   * it. The refresh is cooldown-limited inside the registry, so a flood of forged kids cannot turn
   * this into one database query per request, and it happens here rather than inside a resolver,
   * which is what keeps the resolvers synchronous.
   *
   * Both attempts rethrow anything that is not a TokenVerificationError. Only a verification failure
   * is the caller's fault; a TypeError or an unexpected jose exception is ours, and collapsing one of
   * those into a 401 would hide a server bug behind a status code that gets no attention. The retry
   * path needs this as much as the first attempt does, because the refresh in between means the
   * second call runs against a different snapshot and can therefore fail in ways the first did not.
   */
  async verify(token: string): Promise<AccessTokenClaims> {
    let payload: Record<string, unknown>;
    try {
      payload = await this.verifyOnce(token);
    } catch (first) {
      if (!(first instanceof TokenVerificationError)) throw first;
      await this.keys.refreshIfStale();
      try {
        payload = await this.verifyOnce(token);
      } catch (second) {
        if (!(second instanceof TokenVerificationError)) throw second;
        throw new InvalidAccessTokenError();
      }
    }

    // The crypto layer guarantees these claims are present; this narrows their types and rejects a
    // token whose claims are present but the wrong shape.
    const { sub, tid, roles, permissions } = payload;
    if (
      typeof sub !== "string" ||
      typeof tid !== "string" ||
      !isStringArray(roles) ||
      !isStringArray(permissions)
    ) {
      throw new InvalidAccessTokenError();
    }
    return { sub, tid, roles, permissions };
  }

  // Only the claims are wanted here. The request path has no use for the headers the codec also
  // returns: which key verified the token is an operational question, not an authorization one.
  private async verifyOnce(token: string): Promise<Record<string, unknown>> {
    const { claims } = await verifyNestedToken(token, this.keys.resolvers(), this.policy);
    return claims;
  }
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}
