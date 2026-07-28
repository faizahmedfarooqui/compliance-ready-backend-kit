import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Envelope encryption, and the reason the key registry is a control rather than a liability.
 *
 * A table of private keys sitting in the same database as the data those keys protect is not key
 * management; it means one compromise yields both. So `config_keys` stores only WRAPPED key
 * material: ciphertext produced by a key-encrypting key (KEK) that never enters Postgres. In
 * production the KEK lives in KMS, an HSM, or an enclave and only ever performs wrap/unwrap. This
 * interface is the seam that makes that substitution possible, and the reason the kit is not
 * coupled to one cloud.
 *
 * PCI-DSS Req 3.6 and 3.7 (key-management processes and key lifecycle) are the controls this is
 * aimed at. NOTE: the precise sub-requirement governing acceptable storage forms for private keys
 * has NOT been verified against the standard text, which is behind registration. Confirm it
 * against your licensed copy before citing a clause number in an assessment.
 */
export interface KeyProvider {
  /**
   * Identifies which KEK produced a wrapped blob, recorded alongside it in the registry. Without
   * it, a deployment that has rotated or migrated KEKs cannot tell which keys it can still
   * unwrap, and discovers the answer during an incident.
   */
  readonly id: string;

  /** Encrypt key material for storage. */
  wrap(plaintext: Uint8Array, context: KeyContext): Promise<Uint8Array>;

  /** Decrypt stored key material. Throws if the context does not match the one used to wrap. */
  unwrap(ciphertext: Uint8Array, context: KeyContext): Promise<Uint8Array>;
}

/**
 * Additional authenticated data bound into the wrap.
 *
 * This is not decoration. Without it a wrapped blob is interchangeable: an attacker with write
 * access to the registry could move the ciphertext of a retired signing key into the row for the
 * active encryption key, and unwrapping would succeed. Binding purpose and kid means a blob only
 * decrypts in the exact slot it was created for, and any swap fails the authentication tag.
 */
export interface KeyContext {
  /** What the key is for, e.g. "token_signing". */
  purpose: string;
  /** The key id this material belongs to. */
  kid: string;
}

/** Serialise the context deterministically, so wrap and unwrap always agree byte for byte. */
function aad(context: KeyContext): Uint8Array {
  return new TextEncoder().encode(`v1:${context.purpose}:${context.kid}`);
}

const KEK_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * A KeyProvider backed by a local AES-256-GCM key from configuration.
 *
 * FOR DEVELOPMENT, CI, AND SELF-HOSTED DEPLOYMENTS THAT ACCEPT THE TRADE-OFF. The KEK is held in
 * process memory, which means it is only as protected as the process and its configuration. That
 * is strictly better than storing unwrapped keys in the database, and strictly worse than a KEK
 * that cannot leave a hardware boundary. Use the KMS adapter where a compliance obligation
 * applies.
 *
 * Wire format: `iv (12 bytes) || ciphertext || tag (16 bytes)`. Self-describing enough to unwrap
 * without extra columns, and versioned through the AAD prefix rather than a magic byte.
 */
export class LocalKeyProvider implements KeyProvider {
  readonly id: string;
  private readonly kek: Uint8Array;

  constructor(kek: Uint8Array, id = "local") {
    if (kek.byteLength !== KEK_BYTES) {
      throw new Error(
        `Key-encrypting key must be exactly ${KEK_BYTES} bytes, got ${kek.byteLength}`,
      );
    }
    this.kek = kek;
    this.id = id;
  }

  /*
   * These two are `async` with nothing to await, which `require-await` normally objects to. It is
   * wrong here, and the disable is deliberate rather than convenient:
   *
   * The async signature belongs to the KeyProvider CONTRACT, not to this implementation. A KMS or
   * enclave adapter performs a network round trip and must be async; this adapter happens to be
   * able to answer synchronously. `async` is also what makes the contract honest, because Node's
   * cipher API throws synchronously: a method declared `Promise<T>` that called it directly would
   * hand a caller writing `.catch(handle)` an uncaught exception instead of running the handler.
   * The unit tests caught exactly that. Wrapping the body in a helper fixed it too, but only by
   * introducing an error-normalising branch that no test could reach, and an untestable branch is
   * worse than a justified disable.
   */
  /* eslint-disable @typescript-eslint/require-await */
  async wrap(plaintext: Uint8Array, context: KeyContext): Promise<Uint8Array> {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.kek, iv);
    cipher.setAAD(aad(context));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return new Uint8Array(Buffer.concat([iv, body, cipher.getAuthTag()]));
  }

  async unwrap(ciphertext: Uint8Array, context: KeyContext): Promise<Uint8Array> {
    if (ciphertext.byteLength <= IV_BYTES + TAG_BYTES) {
      throw new Error("Wrapped key is too short to be well formed");
    }
    const buf = Buffer.from(ciphertext);
    const iv = buf.subarray(0, IV_BYTES);
    const body = buf.subarray(IV_BYTES, buf.length - TAG_BYTES);
    const tag = buf.subarray(buf.length - TAG_BYTES);

    const decipher = createDecipheriv("aes-256-gcm", this.kek, iv);
    decipher.setAAD(aad(context));
    decipher.setAuthTag(tag);
    // GCM verifies the tag on final(), so a wrong KEK, a tampered blob, or a mismatched context
    // all surface here rather than returning plausible-looking garbage.
    return new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]));
  }
  /* eslint-enable @typescript-eslint/require-await */
}
