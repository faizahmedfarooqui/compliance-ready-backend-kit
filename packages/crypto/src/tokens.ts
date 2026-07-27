import { CompactEncrypt, SignJWT, compactDecrypt, jwtVerify } from "jose";

/**
 * Access tokens as NESTED JWTs: the claims are signed (JWS), then that signature is
 * encrypted (JWE). Decoding runs the other way, JWE then JWS.
 *
 * Why encrypt at all, stated honestly. A signed-only JWT is tamper-evident but its payload
 * is plaintext base64url, so anyone holding the token, including the browser it was issued
 * to and the end user, can read the tenant id, user id, and the complete list of roles and
 * permissions the principal holds. Encrypting the payload closes that, which is the threat
 * RFC 9068 section 6 names: "it now becomes possible for clients and potentially even end
 * users to directly peek inside the token claims collection of unencrypted tokens".
 *
 * What it does NOT do, so nobody mistakes this for more than it is:
 *  - It is not a substitute for TLS. RFC 8725 (BCP 225) section 3.2 says outright that if a
 *    JWT is protected end-to-end by a transport layer using current algorithms, "there may
 *    be no need to apply another layer of cryptographic protections to the JWT".
 *  - It does not mitigate token theft or replay. The result is still a bearer credential.
 *    RFC 9700 (BCP 240) section 2.2.1 points at sender-constraining (mTLS, DPoP) for that,
 *    and this kit implements neither.
 *  - It does not hide the size of the claim set. RFC 8725 section 2.4 notes encryption leaks
 *    plaintext length, so token length still reveals roughly how many permissions a
 *    principal holds. Compressing to disguise that is forbidden by section 3.6, which is why
 *    decryption below sets maxDecompressedLength to 0 and rejects compressed tokens outright.
 *
 * Order is sign-then-encrypt, per RFC 7519 section 11.2: "normally producers should sign the
 * message and then encrypt the result (thus encrypting the signature). This prevents attacks
 * in which the signature is stripped, leaving just an encrypted message".
 */

/**
 * Inner JWS algorithm: HS256, symmetric.
 *
 * This is a deliberate v0.1 choice with a known expiry date, not a default nobody thought
 * about, so here is the trade-off in full.
 *
 * HS256 uses one shared secret to both sign and verify. That means **any party able to verify
 * a token is also able to mint one**. Today exactly one service issues and verifies these
 * tokens, so that set has one member and the property costs nothing.
 *
 * It stops being acceptable the moment a second service needs to verify a token it did not
 * issue. Handing that service the verification key would hand it the ability to forge
 * arbitrary claims, including `roles` and `permissions` for any tenant. At that point switch
 * the inner layer to an asymmetric algorithm (ES256, or EdDSA/Ed25519), keep the private key
 * in the auth service alone, and publish the public key so verifiers can check signatures
 * without being able to produce them.
 *
 * Worth noting that the asymmetric switch still buys real separation even though the outer
 * JWE layer stays symmetric. Every party that must *decrypt* needs the shared A256KW key, so a
 * compromised verifier could read tokens and even re-encrypt a payload of its choosing, but
 * without the private signing key it still could not produce a valid inner signature, which is
 * what verification actually turns on. Confidentiality and authenticity fail independently.
 *
 * RFC 7518 §3.2 requires a key at least the size of the hash output for this algorithm:
 * "A key of the same size as the hash output (for instance, 256 bits for "HS256") or larger
 * MUST be used". `jose` does not enforce that (it will sign with a 4-byte key), so the 32-byte
 * floor is enforced by config and again in assertKeys below.
 */
const JWS_ALG = "HS256";

/**
 * Outer JWE key management and content encryption.
 *
 * A256KW rather than `dir`. Under `dir` the long-lived shared key IS the content encryption
 * key, so RFC 7518 section 8.4's limit on the number of AES-GCM invocations under a single
 * key binds that one key directly and forever. A256KW mints a fresh random content
 * encryption key per token and wraps it, and section 8.4 states the consideration "does not
 * apply to the composite AES-CBC HMAC SHA-2 or AES Key Wrap algorithms".
 */
const JWE_ALG = "A256KW";
const JWE_ENC = "A256GCM";

/**
 * Explicit media type for the inner JWS, per RFC 8725 section 3.11 (use explicit typing).
 *
 * Deliberately NOT "at+jwt". RFC 9068 section 2.1 makes that value an assertion of
 * conformance to its profile, and this token does not conform: RFC 9068 section 2.2 lists
 * `client_id` as a required claim, which the kit does not issue, and section 2.1 requires
 * RS256 to be among the supported signature algorithms, which the kit does not support.
 * Stamping "at+jwt" would be a false conformance claim.
 */
const TOKEN_TYP = "crbk-at+jwt";

/**
 * RFC 7519 section 5.2: for a nested JWT the outer `cty` "MUST be present; in this case, the
 * value MUST be \"JWT\", to indicate that a Nested JWT is carried in this JWT". jose neither
 * sets nor checks this, so both sides are done explicitly here.
 */
const NESTED_CTY = "JWT";

/** Both keys are exactly 32 bytes: required by A256KW, and >= the HS256 hash size. */
export const TOKEN_KEY_BYTES = 32;

export interface TokenKeys {
  /** HS256 signing key for the inner JWS. */
  signingKey: Uint8Array;
  /** A256KW wrapping key for the outer JWE. MUST be a different key from signingKey. */
  encryptionKey: Uint8Array;
}

export interface TokenPolicy {
  issuer: string;
  audience: string;
  ttlSeconds: number;
  /** Leeway for clock skew between issuer and verifier, in seconds. */
  clockToleranceSeconds?: number;
}

/** Raised for every verification failure, with no detail about which check failed. */
export class TokenVerificationError extends Error {
  constructor(reason: string) {
    super(`Access token rejected: ${reason}`);
    this.name = "TokenVerificationError";
  }
}

function assertKeys(keys: TokenKeys): void {
  for (const [name, key] of [
    ["signingKey", keys.signingKey],
    ["encryptionKey", keys.encryptionKey],
  ] as const) {
    if (key.byteLength !== TOKEN_KEY_BYTES) {
      throw new Error(`${name} must be exactly ${TOKEN_KEY_BYTES} bytes, got ${key.byteLength}`);
    }
  }
  // Key separation. Reusing one secret for both the signature and the encryption couples
  // two independent security properties: recovering it forges tokens AND decrypts them.
  // jose will not stop you, so this is checked here.
  if (Buffer.from(keys.signingKey).equals(Buffer.from(keys.encryptionKey))) {
    throw new Error("signingKey and encryptionKey must be different keys");
  }
}

/**
 * Sign the claims, then encrypt the signed token. Returns a 5-segment compact JWE whose
 * plaintext is a 3-segment compact JWS.
 */
export async function issueNestedToken(
  claims: Record<string, unknown>,
  keys: TokenKeys,
  policy: TokenPolicy,
): Promise<string> {
  assertKeys(keys);

  const jws = await new SignJWT(claims)
    .setProtectedHeader({ alg: JWS_ALG, typ: TOKEN_TYP })
    .setIssuer(policy.issuer)
    .setAudience(policy.audience)
    .setIssuedAt()
    .setExpirationTime(`${policy.ttlSeconds}s`)
    .sign(keys.signingKey);

  // Nothing is replicated onto the outer header: no iss, sub, aud, exp, iat or tid. Copying
  // a claim outside the ciphertext would hand back exactly the information the encryption
  // is there to withhold.
  return new CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader({ alg: JWE_ALG, enc: JWE_ENC, cty: NESTED_CTY, typ: TOKEN_TYP })
    .encrypt(keys.encryptionKey);
}

/**
 * Decrypt, then verify the inner signature. Both layers are validated, as required by
 * RFC 8725 section 3.3: "the entire JWT MUST be rejected if any of them fail to validate
 * ... also for Nested JWTs in which both outer and inner operations MUST be validated".
 *
 * Decrypting alone is NOT enough and is the mistake this function exists to prevent
 * (RFC 8725 section 2.3, incorrect composition of encryption and signature): anyone holding
 * the encryption key could otherwise encrypt a claims set of their choosing and have it
 * accepted, because nothing would ever check the signature.
 */
export async function verifyNestedToken(
  token: string,
  keys: TokenKeys,
  policy: TokenPolicy,
): Promise<Record<string, unknown>> {
  assertKeys(keys);

  let plaintext: Uint8Array;
  let cty: string | undefined;
  try {
    // Algorithms are allow-listed rather than taken from the token's own header, so a
    // token cannot nominate a weaker algorithm than the one we intend to require.
    const decrypted = await compactDecrypt(token, keys.encryptionKey, {
      keyManagementAlgorithms: [JWE_ALG],
      contentEncryptionAlgorithms: [JWE_ENC],
      // RFC 8725 section 3.6: never accept a compressed JWE. 0 rejects them outright
      // instead of exposing a decompression bomb.
      maxDecompressedLength: 0,
    });
    plaintext = decrypted.plaintext;
    cty = decrypted.protectedHeader.cty;
  } catch {
    throw new TokenVerificationError("decryption failed");
  }

  if (cty !== NESTED_CTY) {
    throw new TokenVerificationError("outer header is not a nested JWT");
  }

  try {
    const { payload } = await jwtVerify(new TextDecoder().decode(plaintext), keys.signingKey, {
      algorithms: [JWS_ALG],
      issuer: policy.issuer,
      audience: policy.audience,
      typ: TOKEN_TYP,
      requiredClaims: ["sub", "tid", "roles", "permissions", "iss", "aud", "exp", "iat"],
      clockTolerance: policy.clockToleranceSeconds ?? 0,
    });
    return payload;
  } catch {
    throw new TokenVerificationError("signature or claims invalid");
  }
}
