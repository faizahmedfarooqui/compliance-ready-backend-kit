import { createHash } from "node:crypto";

/**
 * The hash chain that makes the audit log tamper-evident.
 *
 * Each event carries the hash of the one before it, so altering any event invalidates every hash
 * after it. That does not make the log immutable, and the distinction matters for what can honestly
 * be claimed: immutability is enforced by Postgres (triggers and revoked privileges), while the chain
 * makes a change that got past those enforcement layers DETECTABLE rather than impossible.
 *
 * Pure by design, like the token codec beside it. No database, no clock, no key. Everything that
 * decides a hash is an argument, which is what lets the writer and the verifier share one
 * implementation instead of maintaining two that must agree.
 */

/**
 * Domain separator. Included in every hash so a digest computed for one purpose cannot be replayed
 * as one computed for another, and so a future change to the hash construction can be introduced
 * without silently invalidating existing chains: bump the version, and old rows keep verifying under
 * the old label while new rows use the new one.
 */
const HASH_DOMAIN = "crbk.audit.v1";

/** SHA-256 output, and therefore the width of every link in the chain. */
export const AUDIT_HASH_BYTES = 32;

/**
 * What the first event in a chain points at.
 *
 * A fixed value rather than NULL, and that is a deliberate schema decision. With NULL as the genesis
 * marker, a UNIQUE constraint on `prev_hash` would not stop a second genesis row, because Postgres
 * permits many NULLs in a unique index. Making genesis a real value lets that constraint carry its
 * full meaning: exactly one row may follow any given hash, INCLUDING the start, so the chain cannot
 * fork even if the application's locking is wrong.
 */
export const GENESIS_HASH: Buffer = Buffer.alloc(AUDIT_HASH_BYTES, 0);

/**
 * Metadata is a flat map of STRING values, and the restriction is load bearing rather than laziness.
 *
 * The hash is computed by the application and then verified against what Postgres returns, so any
 * normalisation the database performs in between shows up as a broken chain. `jsonb` normalises more
 * than people expect: it sorts keys, discards whitespace, drops duplicate keys, and rewrites numbers,
 * so `1e2` comes back as `100`. Canonical serialisation handles key order and whitespace, but a hash
 * over a number the database is free to rewrite is a hash that fails for reasons that have nothing to
 * do with tampering, and it would fail intermittently, on whichever events happened to carry a number
 * in an unusual form.
 *
 * Strings round-trip through `jsonb` exactly. Restricting to them removes the whole class of problem
 * by construction rather than by care. Callers stringify at the edge, which also forces a decision
 * about how a value should read in an audit trail instead of dumping an object into it.
 */
export type AuditMetadata = Readonly<Record<string, string>>;

/** The evidence an event records. Every field is part of the hash. */
export interface AuditEventInput {
  /** Dotted action name, e.g. "auth.login.succeeded". */
  readonly action: string;
  readonly actorType: string;
  /** Who acted, when that is known. Null for an unauthenticated caller. */
  readonly actorId: string | null;
  readonly resourceType: string | null;
  readonly resourceId: string | null;
  /** Correlates the event with the request that produced it, and with the server log. */
  readonly traceId: string | null;
  readonly sourceIp: string | null;
  /**
   * When the event happened, as an ISO-8601 string in UTC.
   *
   * A string rather than a Date because a Date has to be serialised to be hashed, and then the
   * serialisation is the thing that must match on the way back out. Passing the string makes that
   * explicit and removes any dependence on how a driver renders a timestamp.
   */
  readonly occurredAt: string;
  readonly metadata: AuditMetadata;
}

/**
 * Deterministic serialisation of one event.
 *
 * Not `JSON.stringify` on its own: that preserves insertion order, so two callers building the same
 * event with fields assigned in a different order would produce different bytes and therefore
 * different hashes for identical evidence. Keys are sorted, so the form depends only on content.
 *
 * Length-prefixed rather than delimiter-joined. A separator alone is ambiguous, because a value may
 * contain the separator: `action="a"` with `actorId="b|c"` and `action="a|b"` with `actorId="c"` join
 * to the same string, so two different events would share a hash. Prefixing each value with its
 * byte length makes the encoding injective, which is the property a hash input needs.
 */
export function canonicalAuditForm(event: AuditEventInput): string {
  const scalars: Record<string, string | null> = {
    action: event.action,
    actorType: event.actorType,
    actorId: event.actorId,
    occurredAt: event.occurredAt,
    resourceId: event.resourceId,
    resourceType: event.resourceType,
    sourceIp: event.sourceIp,
    traceId: event.traceId,
  };

  const parts: string[] = [];
  for (const key of Object.keys(scalars).sort()) {
    const value = scalars[key];
    // A null is encoded distinctly from an empty string. Otherwise "no actor recorded" and "an actor
    // whose id is the empty string" would hash identically, and the first is a normal state.
    parts.push(value === null ? `${key}:null` : `${key}:${byteLength(value)}:${value}`);
  }

  for (const key of Object.keys(event.metadata).sort()) {
    const value = event.metadata[key];
    parts.push(`meta.${byteLength(key)}:${key}:${byteLength(value)}:${value}`);
  }

  return `${HASH_DOMAIN}\n${parts.join("\n")}`;
}

/**
 * The hash for one event, given its predecessor's.
 *
 * `prevHash` is folded in as raw bytes ahead of the canonical form, so the digest depends on the
 * entire history rather than on this event alone. That is what makes the structure a chain: changing
 * an early event changes its hash, which changes the input to the next hash, and so on to the head.
 *
 * `seq` is deliberately NOT hashed. It is assigned by a database sequence at insert time, so it is
 * not known while the hash is being computed, and it cannot be altered afterwards because UPDATE on
 * the table raises. It orders rows for reading; the chain, not the column, carries the integrity.
 */
export function computeAuditHash(event: AuditEventInput, prevHash: Buffer): Buffer {
  if (prevHash.byteLength !== AUDIT_HASH_BYTES) {
    throw new Error(
      `prevHash must be exactly ${AUDIT_HASH_BYTES} bytes, got ${prevHash.byteLength}. ` +
        `Use GENESIS_HASH for the first event in a chain.`,
    );
  }
  return createHash("sha256").update(prevHash).update(canonicalAuditForm(event), "utf8").digest();
}

/** One event as stored, which is the input plus what the database assigned. */
export interface StoredAuditEvent extends AuditEventInput {
  readonly seq: bigint;
  readonly prevHash: Buffer;
  readonly hash: Buffer;
}

export interface ChainBreak {
  readonly seq: bigint;
  /** What is wrong, in terms an operator can act on. */
  readonly reason: string;
  readonly expected?: string;
  readonly actual?: string;
}

/**
 * Walk a chain in sequence order and report the FIRST break, or null if it holds.
 *
 * First rather than all, because after a break every later link fails too: one altered event makes
 * the rest of the chain mismatch, and a verifier that reported all of them would bury the one row
 * that matters under thousands of consequences. The seq it returns is where to look.
 *
 * Three distinct failures, kept distinct because they mean different things to whoever is
 * investigating:
 *
 *  - a recomputed hash that does not match the stored one means the EVENT's own fields were altered
 *  - a `prevHash` that does not match the previous row's `hash` means an event was removed or the
 *    order was changed
 *  - a first row whose `prevHash` is not the genesis value means events were removed from the start
 *
 * Deliberately takes an array rather than a cursor. The caller decides how to page; this stays pure
 * and testable, which for the one function that decides whether the evidence is trustworthy is worth
 * more than streaming convenience.
 */
export function verifyAuditChain(
  events: readonly StoredAuditEvent[],
  /** The hash the first supplied event should point at. GENESIS_HASH when verifying from the start. */
  expectedFirstPrevHash: Buffer = GENESIS_HASH,
): ChainBreak | null {
  let expectedPrev = expectedFirstPrevHash;

  for (const event of events) {
    if (!event.prevHash.equals(expectedPrev)) {
      return {
        seq: event.seq,
        reason: expectedPrev.equals(GENESIS_HASH)
          ? "first event does not start from the genesis hash, so earlier events were removed"
          : "prev_hash does not match the previous event's hash, so an event was removed or reordered",
        expected: expectedPrev.toString("hex"),
        actual: event.prevHash.toString("hex"),
      };
    }

    const recomputed = computeAuditHash(event, event.prevHash);
    if (!recomputed.equals(event.hash)) {
      return {
        seq: event.seq,
        reason: "stored hash does not match the event's contents, so a field was altered",
        expected: recomputed.toString("hex"),
        actual: event.hash.toString("hex"),
      };
    }

    expectedPrev = event.hash;
  }

  return null;
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}
