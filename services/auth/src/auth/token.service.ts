import { Inject, Injectable } from "@nestjs/common";
import {
  TokenVerificationError,
  issueNestedToken,
  verifyNestedToken,
  type TokenKeys,
  type TokenPolicy,
} from "@compliance-kit/crypto";
import type { AppConfig } from "@compliance-kit/config";
import { InvalidAccessTokenError, type AccessTokenClaims } from "@compliance-kit/common";
import { CONFIG } from "../core/tokens";

/**
 * Issues and verifies access tokens. The nested-JWT mechanics live in
 * @compliance-kit/crypto; this binds them to the validated config and to the kit's claim
 * shape, and it is the only place either operation happens.
 */
@Injectable()
export class TokenService {
  private readonly keys: TokenKeys;
  private readonly policy: TokenPolicy;

  constructor(@Inject(CONFIG) config: AppConfig) {
    // Decoded once at construction so a malformed key fails at boot, not on first login.
    this.keys = {
      signingKey: new Uint8Array(Buffer.from(config.jwtSigningKey, "base64url")),
      encryptionKey: new Uint8Array(Buffer.from(config.jwtEncryptionKey, "base64url")),
    };
    this.policy = {
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
      ttlSeconds: config.jwtAccessTtlSeconds,
      // A small allowance for clock skew between the issuer and any future verifier.
      clockToleranceSeconds: 5,
    };
  }

  issue(claims: AccessTokenClaims): Promise<string> {
    return issueNestedToken({ ...claims }, this.keys, this.policy);
  }

  /**
   * Verify a token and return its claims, or throw InvalidAccessTokenError.
   *
   * Every failure mode collapses to one error with one message. Distinguishing "expired"
   * from "bad signature" from "wrong audience" in the response would tell an attacker which
   * part of a forged token to fix next.
   */
  async verify(token: string): Promise<AccessTokenClaims> {
    let payload: Record<string, unknown>;
    try {
      payload = await verifyNestedToken(token, this.keys, this.policy);
    } catch (err) {
      if (err instanceof TokenVerificationError) throw new InvalidAccessTokenError();
      throw err;
    }

    // The crypto layer guarantees these claims are present; this narrows their types and
    // rejects a token whose claims are present but the wrong shape.
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
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}
