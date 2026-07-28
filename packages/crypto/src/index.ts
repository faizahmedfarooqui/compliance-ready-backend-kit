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
  type TokenKeys,
  type TokenPolicy,
} from "./tokens";
