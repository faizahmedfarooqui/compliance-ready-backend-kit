import type { CryptoKey, JWK } from "jose";
import type { KeyProvider } from "./key-provider";
import {
  ENCRYPTION_ALG,
  ENCRYPTION_KEY_BYTES,
  SIGNING_ALG,
  derivePublicJwk,
  importSigningKey,
  importVerificationKey,
  sameKeyMaterial,
} from "./key-material";

/**
 * Turning a stored registry row into a key the codec may use, in exactly one place.
 *
 * Two programs load keys: the service's KeyRegistryService, and the `keys:decode` CLI, which promises
 * to verify a token "exactly as" the service does. They used to carry separate loops, and the CLI's
 * copy skipped every protection the service's had: it imported the verification key straight from the
 * stored public JWK, never checked `kek_id`, let one unreadable row abort the whole command, and never
 * consulted `not_after`, so it could call a token valid that the service would refuse. Both now load
 * through `loadStoredKey` and decide usability with `isKeyUsable`, so the two cannot drift again.
 */

/** The columns of a `config_keys` row that loading reads. Structural, so this package needs no database. */
export interface StoredKeyRow {
  kid: string;
  purpose: string;
  algorithm: string;
  wrappedKey: Uint8Array | null;
  kekId: string;
  publicJwk: unknown;
}

export interface LoadedSigningKey {
  purpose: "token_signing";
  kid: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** Built from verified parts, never the stored object, so it is what the JWKS may publish. */
  publicJwk: JWK;
}

export interface LoadedEncryptionKey {
  purpose: "token_encryption";
  kid: string;
  secret: Uint8Array;
}

export type LoadedKey = LoadedSigningKey | LoadedEncryptionKey;

/** JWK members that only a private or symmetric key has. None may appear in a published public key. */
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/**
 * Unwrap and check one stored row, or throw saying why it cannot be trusted.
 *
 * Throwing is how a caller learns to skip the row: callers load row by row and log the reason, so one
 * bad row costs that key and not every key.
 *
 * For a signing key, everything that verifies or gets published is derived from the private half the
 * KEK protects. The stored public JWK must agree with it on the key material AND on its metadata: its
 * `kid` must be the row's, and `alg` and `use`, where present, must be the only values this key is used
 * with. The metadata matters as much as the point. The JWKS used to publish the stored object verbatim,
 * so a JWK whose `kid` differed from its row's was accepted, and tokens signed under the row's kid would
 * then be unresolvable by every external verifier reading the JWKS.
 */
export async function loadStoredKey(provider: KeyProvider, row: StoredKeyRow): Promise<LoadedKey> {
  if (!row.wrappedKey) throw new Error("the row holds no key material");
  // `kek_id` exists so a deployment can tell which rows it can unwrap; checked rather than discovered
  // by a failed unwrap, so the reason names the actual cause.
  if (row.kekId !== provider.id) {
    throw new Error(
      `it was wrapped by key-encrypting key "${row.kekId}", and this process holds "${provider.id}"`,
    );
  }

  if (row.purpose === "token_signing") {
    if (row.algorithm !== SIGNING_ALG) {
      throw new Error(`a signing key must be ${SIGNING_ALG}, not ${row.algorithm}`);
    }
    const material = await provider.unwrap(row.wrappedKey, { purpose: row.purpose, kid: row.kid });
    const privatePkcs8 = new TextDecoder().decode(material);
    const publicJwk = trustedPublicJwk(row, await derivePublicJwk(privatePkcs8));
    return {
      purpose: "token_signing",
      kid: row.kid,
      privateKey: await importSigningKey(privatePkcs8),
      publicKey: await importVerificationKey(publicJwk),
      publicJwk,
    };
  }

  if (row.purpose === "token_encryption") {
    if (row.algorithm !== ENCRYPTION_ALG) {
      throw new Error(`an encryption key must be ${ENCRYPTION_ALG}, not ${row.algorithm}`);
    }
    const secret = await provider.unwrap(row.wrappedKey, { purpose: row.purpose, kid: row.kid });
    if (secret.byteLength !== ENCRYPTION_KEY_BYTES) {
      throw new Error(
        `an encryption key must be ${ENCRYPTION_KEY_BYTES} bytes, not ${secret.byteLength}`,
      );
    }
    return { purpose: "token_encryption", kid: row.kid, secret };
  }

  throw new Error(`unknown key purpose "${row.purpose}"`);
}

/**
 * The public JWK to verify with and publish, built from the derived key material and the row's own
 * identity, after checking the stored JWK agrees with both. Throws on any disagreement, since a stored
 * JWK that disagrees with its own row has been edited by something other than the key commands.
 */
function trustedPublicJwk(row: StoredKeyRow, derived: JWK): JWK {
  const stored = row.publicJwk;
  if (typeof stored !== "object" || stored === null || Array.isArray(stored)) {
    throw new Error("the signing key has no public JWK");
  }
  const jwk = stored as JWK;
  if (!sameKeyMaterial(derived, jwk)) {
    throw new Error(
      "its stored public JWK is not the public half of its wrapped private key, so the column may " +
        "have been replaced; refusing to verify or publish with it",
    );
  }
  if (jwk.kid !== row.kid) {
    throw new Error(`its stored public JWK names kid "${String(jwk.kid)}", not the row's own`);
  }
  if (jwk.alg !== undefined && jwk.alg !== SIGNING_ALG) {
    throw new Error(`its stored public JWK declares alg "${jwk.alg}", not ${SIGNING_ALG}`);
  }
  if (jwk.use !== undefined && jwk.use !== "sig") {
    throw new Error(`its stored public JWK declares use "${jwk.use}", not "sig"`);
  }
  const leaked = PRIVATE_MEMBERS.filter((member) => member in jwk);
  if (leaked.length > 0) {
    throw new Error(`its stored public JWK carries private members (${leaked.join(", ")})`);
  }
  return { ...derived, kid: row.kid, alg: SIGNING_ALG, use: "sig" };
}

/**
 * Whether a loaded key may still be used, honouring `not_after` at the point of use.
 *
 * Checked where the key is used rather than trusted to a sweeper: a sweeper that has not run, or that
 * failed, would otherwise leave an expired key verifying tokens indefinitely.
 */
export function isKeyUsable(
  key: { state: string; notAfter: Date | null },
  now: number = Date.now(),
): boolean {
  if (key.state === "revoked" || key.state === "pending") return false;
  if (key.notAfter && key.notAfter.getTime() <= now) return false;
  return true;
}
