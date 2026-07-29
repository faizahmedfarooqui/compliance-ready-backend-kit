import { Controller, Get, Header } from "@nestjs/common";
import { ApiOkResponse, ApiOperation, ApiTags } from "@nestjs/swagger";
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
@ApiTags("keys")
@Controller()
export class JwksController {
  constructor(private readonly keys: KeyRegistryService) {}

  @ApiOperation({
    summary: "Published verification keys (JWKS)",
    description:
      "THE ONE ROUTE WITH NO SUCCESS ENVELOPE. Serves a bare JWK Set, because RFC 7517 defines the " +
      "document as an object with a top-level `keys` array and every standard consumer, including " +
      "jose's `createRemoteJWKSet`, rejects anything else. Wrapping it in `{ success, data, meta }` is " +
      "not a cosmetic difference, it makes the document unusable. Served at the origin root rather than " +
      "under `/api`, because RFC 8615 reserves `/.well-known/` for exactly this.\n\n" +
      "Contains only PUBLIC halves: the active signing key, plus any key in its rotation overlap so " +
      "tokens signed before a rotation still verify. The symmetric encryption key is never here.\n\n" +
      "Publishing these does NOT let a third party verify a kit-issued token on its own. The outer JWE " +
      "layer is symmetric, so a holder of only this document gets ERR_JWS_INVALID; verifying also " +
      "requires being handed the A256KW key, which grants decryption of every token though still not " +
      "the ability to mint one.",
  })
  @ApiOkResponse({
    description: "A JWK Set (RFC 7517), unwrapped.",
    content: {
      "application/jwk-set+json": {
        schema: {
          type: "object",
          required: ["keys"],
          properties: {
            keys: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  kty: { type: "string", example: "EC" },
                  crv: { type: "string", example: "P-256" },
                  x: { type: "string" },
                  y: { type: "string" },
                  // NOT format: uuid, even though every kid this kit generates today happens to be
                  // one. RFC 7517 s4.5 defines kid as an arbitrary case-sensitive string, which is why
                  // config_keys stores it as TEXT rather than uuid: a uuid column turns a hostile
                  // non-uuid kid into a Postgres 22P02 error, so a 500 where a 401 belongs. Publishing
                  // format: uuid would contradict that decision in the one document other systems
                  // actually consume, and a generated client or validator would then reject a perfectly
                  // valid JWKS. That is not hypothetical: a KMS or HSM KeyProvider adapter is on the
                  // roadmap and would supply key ids of its own choosing.
                  kid: { type: "string", example: "9f1c2b7e-4d3a-4b8f-9e2c-5a6d7f8b9c01" },
                  alg: { type: "string", example: "ES256" },
                  use: { type: "string", example: "sig" },
                },
              },
            },
          },
        },
      },
    },
  })
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
