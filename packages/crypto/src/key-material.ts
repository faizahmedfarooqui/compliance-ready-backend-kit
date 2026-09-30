import { randomBytes, randomUUID } from "node:crypto";
import { exportJWK, exportPKCS8, generateKeyPair, importJWK, importPKCS8 } from "jose";
import type { CryptoKey, JWK } from "jose";

/**
 * Generating, serialising and re-importing the two kinds of key the token codec needs.
 *
 * Kept separate from tokens.ts because the lifecycle of a key (create, wrap, store, rotate) is a
 * different concern from using one to sign a request, and because the registry needs to handle key
 * material without knowing anything about JWTs.
 */

/** Inner JWS. ES256 rather than HS256, so a verifier cannot also mint. */
export const SIGNING_ALG = "ES256" as const;

/** Outer JWE key wrapping. A256KW needs exactly a 256-bit key. */
export const ENCRYPTION_ALG = "A256KW" as const;

export const ENCRYPTION_KEY_BYTES = 32;

export type KeyPurpose = "token_signing" | "token_encryption";

export interface GeneratedSigningKey {
  kid: string;
  algorithm: typeof SIGNING_ALG;
  /** PKCS#8 DER-in-PEM. This is the secret half and is only ever stored wrapped. */
  privatePkcs8: string;
  /** Safe to publish. Served from the JWKS endpoint so other services can verify. */
  publicJwk: JWK;
}

export interface GeneratedEncryptionKey {
  kid: string;
  algorithm: typeof ENCRYPTION_ALG;
  /** Raw 256-bit key. Symmetric, so there is no public half and nothing to publish. */
  secret: Uint8Array;
}

/**
 * A fresh key id. Random rather than derived from the key, because a kid derived from the public
 * key (a thumbprint) is stable across rotations of the same key pair and therefore useless for
 * telling two generations apart, which is precisely what rotation needs.
 */
export function newKid(): string {
  return randomUUID();
}

export async function generateSigningKey(): Promise<GeneratedSigningKey> {
  // extractable, because the private half has to be exported to be wrapped and stored.
  const { privateKey, publicKey } = await generateKeyPair(SIGNING_ALG, { extractable: true });
  const kid = newKid();
  const publicJwk = await exportJWK(publicKey);

  return {
    kid,
    algorithm: SIGNING_ALG,
    privatePkcs8: await exportPKCS8(privateKey),
    // `kid`, `alg` and `use` are what makes the JWKS entry usable by a verifier without
    // out-of-band knowledge: it can select the right key and knows what to do with it.
    publicJwk: { ...publicJwk, kid, alg: SIGNING_ALG, use: "sig" },
  };
}

export function generateEncryptionKey(): GeneratedEncryptionKey {
  return {
    kid: newKid(),
    algorithm: ENCRYPTION_ALG,
    secret: new Uint8Array(randomBytes(ENCRYPTION_KEY_BYTES)),
  };
}

/** Re-import a stored private key for signing. */
export function importSigningKey(privatePkcs8: string): Promise<CryptoKey> {
  return importPKCS8(privatePkcs8, SIGNING_ALG, { extractable: false });
}

/**
 * Re-import a published public key for verification.
 *
 * `importJWK` returns `CryptoKey | Uint8Array`, the second for symmetric (`oct`) key material. A
 * real narrowing rather than a cast, because that branch is reachable: hand this an `oct` JWK and
 * it must refuse rather than silently verify with a shared secret, which would put us straight back
 * to a key that can both verify and mint.
 */
export async function importVerificationKey(publicJwk: JWK): Promise<CryptoKey> {
  const key = await importJWK(publicJwk, SIGNING_ALG);
  if (key instanceof Uint8Array) {
    throw new TypeError("Expected an asymmetric public key for ES256, got symmetric key material");
  }
  return key;
}

/**
 * True when `publicJwk` is the public half of `privatePkcs8`.
 *
 * The registry stores the two halves of a signing key in different forms. The private half is wrapped
 * by the KEK, so a write to the database cannot forge it without the KEK. The public half sits in the
 * clear, so any write to the database can replace it, and the public half is what verifies tokens here
 * and what the JWKS hands every other verifier. Without this comparison, anyone able to write
 * `config_keys` could swap in a public key of their own and have tokens they signed accepted, which
 * is the one thing envelope encryption was supposed to make a database compromise unable to do.
 * Deriving the public point from the private key and comparing binds the column to the material the
 * KEK protects.
 *
 * Compares the key material fields only. The metadata a JWK also carries (`kid`, `alg`, `use`) is
 * checked by `loadStoredKey`, which is the one place a stored row becomes a usable key.
 */
export async function publicJwkMatchesPrivateKey(
  privatePkcs8: string,
  publicJwk: JWK,
): Promise<boolean> {
  return sameKeyMaterial(await derivePublicJwk(privatePkcs8), publicJwk);
}

/**
 * The public half of a signing key, derived from its private half: `kty`, `crv`, `x` and `y` only.
 *
 * Derived rather than read from storage, so that what verifies and what gets published follow from the
 * material the KEK protects rather than from a column anyone with database write access can edit.
 */
export async function derivePublicJwk(privatePkcs8: string): Promise<JWK> {
  // Extractable for this derivation only; the key used for signing is imported non-extractable.
  const privateKey = await importPKCS8(privatePkcs8, SIGNING_ALG, { extractable: true });
  const { kty, crv, x, y } = await exportJWK(privateKey);
  return { kty, crv, x, y };
}

/** True when two JWKs describe the same EC public point. */
export function sameKeyMaterial(a: JWK, b: JWK): boolean {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

/** A JWKS document, as served from /.well-known/jwks.json. */
export interface Jwks {
  keys: JWK[];
}

/**
 * Build the JWKS from the public halves of every key a verifier should still accept.
 *
 * Includes retiring keys deliberately: during a rotation overlap, tokens signed by the previous
 * key are still valid until they expire, and a JWKS that dropped the old key the moment a new one
 * became active would invalidate every live token instead of rotating gracefully.
 */
export function toJwks(publicKeys: readonly JWK[]): Jwks {
  return { keys: [...publicKeys] };
}
