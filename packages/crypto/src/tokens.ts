import { CompactEncrypt, SignJWT, compactDecrypt, jwtVerify } from "jose";
import type { CompactJWEHeaderParameters, CryptoKey, JWTHeaderParameters } from "jose";
import { ENCRYPTION_ALG, ENCRYPTION_KEY_BYTES, SIGNING_ALG } from "./key-material";

/**
 * Access tokens as NESTED JWTs: the claims are signed (JWS), then that signature is encrypted
 * (JWE). Decoding runs the other way, JWE then JWS.
 *
 * Why encrypt at all, stated honestly. A signed-only JWT is tamper-evident but its payload is
 * plaintext base64url, so anyone holding the token, including the browser it was issued to and the
 * end user, can read the tenant id, user id, and the complete list of roles and permissions the
 * principal holds. Encrypting the payload closes that, which is the threat RFC 9068 section 6
 * names: "it now becomes possible for clients and potentially even end users to directly peek
 * inside the token claims collection of unencrypted tokens".
 *
 * What it does NOT do, so nobody mistakes this for more than it is:
 *  - It is not a substitute for TLS. RFC 8725 (BCP 225) section 3.2 says outright that if a JWT is
 *    protected end-to-end by a transport layer using current algorithms, "there may be no need to
 *    apply another layer of cryptographic protections to the JWT".
 *  - It does not mitigate token theft or replay. The result is still a bearer credential.
 *    RFC 9700 (BCP 240) section 2.2.1 points at sender-constraining (mTLS, DPoP) for that, and this
 *    kit implements neither.
 *  - It does not hide the size of the claim set. RFC 8725 section 2.4 notes encryption leaks
 *    plaintext length, so token length still reveals roughly how many permissions a principal
 *    holds. Compressing to disguise that is forbidden by section 3.6, which is why decryption below
 *    sets maxDecompressedLength to 0 and rejects compressed tokens outright.
 *
 * Order is sign-then-encrypt, per RFC 7519 section 11.2: "normally producers should sign the
 * message and then encrypt the result (thus encrypting the signature). This prevents attacks in
 * which the signature is stripped, leaving just an encrypted message".
 *
 * This module is deliberately PURE: it holds no keys, reads no database and knows nothing about
 * tenants. Key lifecycle lives in the registry that supplies the material and the resolvers.
 */

/**
 * Inner JWS algorithm.
 *
 * ES256, not HS256. HS256 uses one shared secret to sign and verify, so anything able to verify a
 * token is also able to mint one. That is tolerable while a single service does both and wrong the
 * moment a second service verifies tokens it did not issue, because handing it the verification key
 * would hand it the power to forge any claim, for any tenant. With ES256 a verifier receives only
 * the public half. RFC 7518 section 3.1 rates ES256 "Recommended+", above RS256's "Recommended".
 */
const JWS_ALG = SIGNING_ALG;

/**
 * Outer JWE key management and content encryption.
 *
 * A256KW rather than `dir`. Under `dir` the long-lived shared key IS the content encryption key, so
 * RFC 7518 section 8.4's limit on AES-GCM invocations under a single key binds that one key
 * directly and forever. A256KW mints a fresh random content encryption key per token and wraps it,
 * and section 8.4 states the consideration "does not apply to the composite AES-CBC HMAC SHA-2 or
 * AES Key Wrap algorithms".
 */
const JWE_ALG = ENCRYPTION_ALG;
const JWE_ENC = "A256GCM";

/**
 * Explicit media type for the inner JWS, per RFC 8725 section 3.11 (use explicit typing).
 *
 * Deliberately NOT "at+jwt". RFC 9068 section 2.1 makes that value an assertion of conformance to
 * its profile, and this token does not conform: section 2.2 lists `client_id` as a required claim,
 * which the kit does not issue, and section 2.1 requires RS256 to be among the supported signature
 * algorithms, which the kit does not support. Stamping "at+jwt" would be a false conformance claim.
 */
const TOKEN_TYP = "crbk-at+jwt";

/**
 * RFC 7519 section 5.2: for a nested JWT the outer `cty` "MUST be present; in this case, the value
 * MUST be \"JWT\", to indicate that a Nested JWT is carried in this JWT". jose neither sets nor
 * checks this, so both sides are done explicitly here.
 */
const NESTED_CTY = "JWT";

/** A256KW requires exactly a 256-bit key. */
export const TOKEN_KEY_BYTES = ENCRYPTION_KEY_BYTES;

/** The key that signs the inner JWS, and the `kid` naming it in the header. */
export interface SigningMaterial {
  kid: string;
  key: CryptoKey;
}

/** The key that wraps the content encryption key, and the `kid` naming it. */
export interface EncryptionMaterial {
  kid: string;
  key: Uint8Array;
}

export interface TokenMaterial {
  signing: SigningMaterial;
  encryption: EncryptionMaterial;
}

/**
 * Key resolvers, keyed by the `kid` in a token header.
 *
 * SYNCHRONOUS ON PURPOSE, and this is the single most important line in the file.
 *
 * jose's own documentation for these functions warns that "No token components have been verified
 * at the time of this function call". The `kid` is therefore attacker-controlled input. If resolving
 * it could await, an attacker would be able to make an unauthenticated request drive a database
 * query or a KMS unwrap simply by inventing a kid, which is a remote amplification primitive
 * (RFC 8725 section 2.9 covers relying on unverified header parameters). A synchronous resolver can
 * only ever consult memory, so a forged kid costs a map lookup.
 *
 * The two resolvers are separately typed rather than one function taking a purpose. That makes the
 * substitution attack unrepresentable instead of merely guarded against: a signature verification
 * cannot be handed the symmetric encryption key, because the types do not permit it.
 *
 * A resolver returns undefined for an unknown, revoked or expired kid, and the caller turns that
 * into a rejection.
 */
export type SigningKeyResolver = (kid: string) => CryptoKey | undefined;
export type EncryptionKeyResolver = (kid: string) => Uint8Array | undefined;

export interface TokenResolvers {
  signing: SigningKeyResolver;
  encryption: EncryptionKeyResolver;
}

export interface TokenPolicy {
  issuer: string;
  audience: string;
  ttlSeconds: number;
  /** Leeway for clock skew between issuer and verifier, in seconds. */
  clockToleranceSeconds?: number;
}

/**
 * The result of a successful verification: the claims, and the two protected headers that were
 * actually validated to produce them.
 *
 * The headers ride along rather than being obtainable separately, and that is deliberate. Operators
 * need to see which key verified a token, but an `inspectToken` helper that decoded headers WITHOUT
 * verifying would be the RFC 8725 section 2.3 mistake wearing a helpful name: the first caller in a
 * hurry reads a kid or a claim out of it and treats an unverified token as trustworthy. Making the
 * headers a product of verification means there is no way to read them off a token that did not pass.
 *
 * Shaped after jose's own `jwtVerify`, which returns `{ payload, protectedHeader }`.
 */
export interface VerifiedToken {
  claims: Record<string, unknown>;
  /** JWE header. Names the encryption key and carries `cty`. */
  outerHeader: CompactJWEHeaderParameters;
  /** JWS header. Names the signing key whose public half is published in the JWKS. */
  innerHeader: JWTHeaderParameters;
}

/** Raised for every verification failure, with no detail about which check failed. */
export class TokenVerificationError extends Error {
  constructor(reason: string) {
    super(`Access token rejected: ${reason}`);
    this.name = "TokenVerificationError";
  }
}

function assertMaterial(material: TokenMaterial): void {
  if (material.encryption.key.byteLength !== TOKEN_KEY_BYTES) {
    throw new Error(
      `Encryption key must be exactly ${TOKEN_KEY_BYTES} bytes, got ${material.encryption.key.byteLength}`,
    );
  }
  if (!material.signing.kid || !material.encryption.kid) {
    throw new Error("Both signing and encryption material must carry a kid");
  }
  // Distinct kids are not a security requirement (the keys live in separately-typed slots and are
  // resolved by separately-typed resolvers) but a shared kid makes a key-rotation audit trail
  // ambiguous, and ambiguity in that trail is the thing an assessor is reading it for.
  if (material.signing.kid === material.encryption.kid) {
    throw new Error("Signing and encryption keys must have distinct kids");
  }
}

/**
 * Sign the claims, then encrypt the signed token. Returns a 5-segment compact JWE whose plaintext
 * is a 3-segment compact JWS. Both layers name their key with a `kid` so a verifier can pick the
 * right one during a rotation overlap.
 */
export async function issueNestedToken(
  claims: Record<string, unknown>,
  material: TokenMaterial,
  policy: TokenPolicy,
): Promise<string> {
  assertMaterial(material);

  const jws = await new SignJWT(claims)
    .setProtectedHeader({ alg: JWS_ALG, typ: TOKEN_TYP, kid: material.signing.kid })
    .setIssuer(policy.issuer)
    .setAudience(policy.audience)
    .setIssuedAt()
    .setExpirationTime(`${policy.ttlSeconds}s`)
    .sign(material.signing.key);

  // Nothing is replicated onto the outer header beyond what a verifier needs to select a key: no
  // iss, sub, aud, exp, iat or tid. Copying a claim outside the ciphertext would hand back exactly
  // the information the encryption exists to withhold. `kid` is safe because it names a key, not a
  // subject, and the JWKS publishes those names anyway.
  return new CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader({
      alg: JWE_ALG,
      enc: JWE_ENC,
      cty: NESTED_CTY,
      typ: TOKEN_TYP,
      kid: material.encryption.kid,
    })
    .encrypt(material.encryption.key);
}

/**
 * Decrypt, then verify the inner signature. Both layers are validated, as required by RFC 8725
 * section 3.3: "the entire JWT MUST be rejected if any of them fail to validate ... also for Nested
 * JWTs in which both outer and inner operations MUST be validated".
 *
 * Decrypting alone is NOT enough and is the mistake this function exists to prevent (RFC 8725
 * section 2.3, incorrect composition of encryption and signature): anyone holding the encryption key
 * could otherwise encrypt a claims set of their choosing and have it accepted, because nothing would
 * ever check the signature.
 */
export async function verifyNestedToken(
  token: string,
  resolvers: TokenResolvers,
  policy: TokenPolicy,
): Promise<VerifiedToken> {
  let plaintext: Uint8Array;
  let outerHeader: CompactJWEHeaderParameters;
  try {
    // Algorithms are allow-listed rather than taken from the token's own header, so a token cannot
    // nominate a weaker algorithm than the one we intend to require.
    const decrypted = await compactDecrypt(
      token,
      (header) => {
        const kid = header.kid;
        // An absent kid is refused rather than falling back to "the active key". A fallback would
        // let a token minted under a revoked key be accepted simply by omitting the header.
        if (typeof kid !== "string" || kid.length === 0) {
          throw new TokenVerificationError("outer header has no kid");
        }
        const key = resolvers.encryption(kid);
        if (!key) throw new TokenVerificationError("unknown encryption kid");
        return key;
      },
      {
        keyManagementAlgorithms: [JWE_ALG],
        contentEncryptionAlgorithms: [JWE_ENC],
        // RFC 8725 section 3.6: never accept a compressed JWE. 0 rejects them outright instead of
        // exposing a decompression bomb.
        maxDecompressedLength: 0,
      },
    );
    plaintext = decrypted.plaintext;
    outerHeader = decrypted.protectedHeader;
  } catch {
    throw new TokenVerificationError("decryption failed");
  }

  if (outerHeader.cty !== NESTED_CTY) {
    throw new TokenVerificationError("outer header is not a nested JWT");
  }

  try {
    const { payload, protectedHeader } = await jwtVerify(
      new TextDecoder().decode(plaintext),
      (header) => {
        const kid = header.kid;
        if (typeof kid !== "string" || kid.length === 0) {
          throw new TokenVerificationError("inner header has no kid");
        }
        const key = resolvers.signing(kid);
        if (!key) throw new TokenVerificationError("unknown signing kid");
        return key;
      },
      {
        algorithms: [JWS_ALG],
        issuer: policy.issuer,
        audience: policy.audience,
        typ: TOKEN_TYP,
        requiredClaims: ["sub", "tid", "roles", "permissions", "iss", "aud", "exp", "iat"],
        clockTolerance: policy.clockToleranceSeconds ?? 0,
      },
    );
    return { claims: payload, outerHeader, innerHeader: protectedHeader };
  } catch {
    throw new TokenVerificationError("signature or claims invalid");
  }
}
