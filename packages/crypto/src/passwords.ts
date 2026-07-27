import * as argon2 from "argon2";

/**
 * The single definition of how this system hashes a password.
 *
 * It lives in its own package because it has two consumers that must not drift apart:
 * the auth service (registration and login) and the tenant admin seed script. Two copies
 * of these numbers would mean a password hashed by one path and verified by the other at a
 * different work factor, which is the sort of inconsistency an assessor finds and nobody
 * notices in testing.
 *
 * Argon2id, with cost parameters stated explicitly rather than left to library defaults,
 * so that "what key-derivation function, at what work factor" has one readable answer that
 * a dependency upgrade cannot silently change.
 *
 * m=19456 KiB (19 MiB), t=2, p=1 is one of the configurations OWASP's Password Storage
 * Cheat Sheet lists as providing an equivalent level of defence; the listed options trade
 * RAM against CPU. Raise these to the highest values your latency budget tolerates and
 * re-tune on the hardware you actually deploy on. If you do raise them, existing hashes are
 * upgraded transparently on next successful login, see `needsRehash`.
 *
 * PCI-DSS 8.3.2 is the direct control (strong cryptography renders all authentication
 * factors unreadable in storage and transmission). HIPAA names no password-storage
 * safeguard; the nearest standard is 164.312(d) (Person or entity authentication).
 * SOC 2 CC6.1 covers it under logical access.
 */
export const ARGON2_OPTIONS: argon2.HashOptions = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/** Hash a plaintext password for storage. */
export function hashPassword(plaintext: string): Promise<string> {
  return argon2.hash(plaintext, ARGON2_OPTIONS);
}

/**
 * Verify a password against a stored hash. Returns false rather than throwing on a
 * malformed or unrecognised hash, so a corrupt row is a failed login and not a 500.
 */
export async function verifyPassword(storedHash: string, plaintext: string): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, plaintext);
  } catch {
    return false;
  }
}

/**
 * True when a stored hash was produced with weaker parameters than ARGON2_OPTIONS.
 *
 * Raising a work factor only protects passwords hashed after the change, so without this
 * a deployment that tightens its parameters keeps every existing credential at the old
 * strength indefinitely. Call it after a successful verification and re-hash if it returns
 * true: that is the only moment the plaintext is available to re-hash with.
 */
export function needsRehash(storedHash: string): boolean {
  try {
    return argon2.needsRehash(storedHash, {
      memoryCost: ARGON2_OPTIONS.memoryCost,
      timeCost: ARGON2_OPTIONS.timeCost,
      parallelism: ARGON2_OPTIONS.parallelism,
    });
  } catch {
    // An unparseable digest cannot be compared. Treat it as not needing a rehash: the
    // verification that gates this call will have already failed it.
    return false;
  }
}

/**
 * A well-formed Argon2id hash of a value no user can supply. Computed once, lazily.
 */
let decoyHash: Promise<string> | undefined;

/**
 * Burn a comparable amount of CPU when there is no stored hash to verify against, so that
 * "no such user" and "wrong password" are not distinguishable by response time. Without
 * this, the timing of a login endpoint enumerates which email addresses are registered.
 */
export async function verifyAgainstDecoy(plaintext: string): Promise<false> {
  decoyHash ??= hashPassword("decoy-value-never-a-real-password");
  await verifyPassword(await decoyHash, plaintext);
  return false;
}
