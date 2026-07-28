import { Controller, Get, Header } from "@nestjs/common";
import type { Jwks } from "@compliance-kit/crypto";
import { RawResponse } from "../common/raw-response.decorator";
import { KeyRegistryService } from "./key-registry.service";

/**
 * Publishes the public halves of the token signing keys.
 *
 * The path is fixed at `/.well-known/jwks.json` and sits OUTSIDE the `/api` global prefix, because
 * RFC 8615 reserves `/.well-known/` at the root of an origin. A well-known URI nested under a
 * path prefix is not a well-known URI, and a verifier that expects to find it by convention would
 * not.
 *
 * NOT tenant-scoped, and there is no `x-tenant-id` here. Keys are deployment-wide: which tenant a
 * token belongs to is the `tid` claim inside the ciphertext, so a per-tenant key would force a
 * verifier to learn the tenant before it could verify anything. See the ConfigKey model comment.
 *
 * Unauthenticated, which is correct: every value served is a public key, and the whole purpose is
 * for other parties to fetch it without credentials. Nothing secret can reach this response, and
 * `KeyRegistryService.jwks()` filters to published states rather than serialising rows.
 */
@Controller()
export class JwksController {
  constructor(private readonly keys: KeyRegistryService) {}

  @Get(".well-known/jwks.json")
  /**
   * Exempt from the response envelope. RFC 7517 defines a JWK Set as `{ "keys": [...] }` at the top
   * level, so wrapping it in { success, data, meta } produces a document no standard client can
   * read, jose's createRemoteJWKSet included.
   */
  @RawResponse()
  /**
   * Cacheable, but only briefly. Too long and a revoked key stays trusted by verifiers holding a
   * stale copy for the life of their cache; too short and every verifier refetches constantly.
   * Five minutes is short enough that a revocation propagates on a human timescale, and
   * `must-revalidate` stops a cache serving it past expiry when this endpoint is unreachable.
   */
  @Header("cache-control", "public, max-age=300, must-revalidate")
  // RFC 7517 registers this media type for a JWK Set.
  @Header("content-type", "application/jwk-set+json; charset=utf-8")
  jwks(): Jwks {
    return this.keys.jwks();
  }
}
