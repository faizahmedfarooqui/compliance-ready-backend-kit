/**
 * The JOSE types that leak through this package's public API.
 *
 * Re-exported so no other package has to depend on `jose` directly. CLAUDE.md makes this package the
 * only home for anything cryptographic, and a consumer importing `jose` for a type would quietly
 * break that: it would gain the ability to reach for `SignJWT` too, and there would then be two
 * places that know the token format.
 */
export type { CryptoKey, JWK } from "jose";

export {
  ARGON2_OPTIONS,
  hashPassword,
  needsRehash,
  verifyAgainstDecoy,
  verifyPassword,
} from "./passwords";

export { LocalKeyProvider, type KeyContext, type KeyProvider } from "./key-provider";

export {
  ENCRYPTION_ALG,
  ENCRYPTION_KEY_BYTES,
  SIGNING_ALG,
  generateEncryptionKey,
  generateSigningKey,
  importSigningKey,
  importVerificationKey,
  newKid,
  toJwks,
  type GeneratedEncryptionKey,
  type GeneratedSigningKey,
  type Jwks,
  type KeyPurpose,
} from "./key-material";

export {
  TOKEN_KEY_BYTES,
  TokenVerificationError,
  issueNestedToken,
  verifyNestedToken,
  type EncryptionKeyResolver,
  type EncryptionMaterial,
  type SigningKeyResolver,
  type SigningMaterial,
  type TokenMaterial,
  type TokenPolicy,
  type TokenResolvers,
  type VerifiedToken,
} from "./tokens";
