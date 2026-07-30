import { describe, expect, it } from "vitest";
import {
  AUDIT_HASH_BYTES,
  GENESIS_HASH,
  canonicalAuditForm,
  computeAuditHash,
  verifyAuditChain,
  type AuditEventInput,
  type StoredAuditEvent,
} from "./audit-hash";

/**
 * A hash chain that cannot detect tampering is a column of random-looking bytes that makes a log look
 * trustworthy. So the tests that matter here are the ones that alter something and demand the
 * verifier notice: every field individually, a removed event, a reordered pair, a truncated start.
 */

const EVENT: AuditEventInput = {
  action: "auth.login.succeeded",
  actorType: "user",
  actorId: "11111111-1111-4111-8111-111111111111",
  resourceType: "user",
  resourceId: "11111111-1111-4111-8111-111111111111",
  traceId: "22222222-2222-4222-8222-222222222222",
  sourceIp: "203.0.113.7",
  occurredAt: "2026-07-30T09:00:00.000Z",
  metadata: { email: "admin@acme.example" },
};

/** Build a valid chain of n events, each linked to the last. */
function chain(n: number, mutate: (i: number) => Partial<AuditEventInput> = () => ({})) {
  const events: StoredAuditEvent[] = [];
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < n; i += 1) {
    const input: AuditEventInput = { ...EVENT, action: `event.${i}`, ...mutate(i) };
    const hash = computeAuditHash(input, prevHash);
    events.push({ ...input, seq: BigInt(i + 1), prevHash, hash });
    prevHash = hash;
  }
  return events;
}

describe("computeAuditHash", () => {
  it("produces a 32-byte digest", () => {
    expect(computeAuditHash(EVENT, GENESIS_HASH)).toHaveLength(AUDIT_HASH_BYTES);
  });

  it("is deterministic for identical input", () => {
    expect(computeAuditHash(EVENT, GENESIS_HASH)).toEqual(computeAuditHash(EVENT, GENESIS_HASH));
  });

  // The chain property itself: the same event at a different point in history hashes differently.
  it("depends on the predecessor, not only on the event", () => {
    const other = Buffer.alloc(AUDIT_HASH_BYTES, 9);
    expect(computeAuditHash(EVENT, GENESIS_HASH)).not.toEqual(computeAuditHash(EVENT, other));
  });

  it("refuses a predecessor of the wrong width rather than hashing it anyway", () => {
    expect(() => computeAuditHash(EVENT, Buffer.alloc(16))).toThrow(/exactly 32 bytes/);
    expect(() => computeAuditHash(EVENT, Buffer.alloc(0))).toThrow(/GENESIS_HASH/);
  });

  /**
   * Every field must change the hash. A field left out of the hash input is a field an attacker can
   * rewrite for free, and the omission is invisible: the chain still verifies, so the log looks intact
   * while the evidence in it is wrong.
   */
  it.each([
    ["action", { action: "auth.login.failed" }],
    ["actorType", { actorType: "control_plane" }],
    ["actorId", { actorId: "33333333-3333-4333-8333-333333333333" }],
    ["resourceType", { resourceType: "tenant" }],
    ["resourceId", { resourceId: "44444444-4444-4444-8444-444444444444" }],
    ["traceId", { traceId: "55555555-5555-4555-8555-555555555555" }],
    ["sourceIp", { sourceIp: "198.51.100.1" }],
    ["occurredAt", { occurredAt: "2026-07-30T09:00:00.001Z" }],
    ["metadata value", { metadata: { email: "someone.else@acme.example" } }],
    ["metadata key", { metadata: { username: "admin@acme.example" } }],
    ["an added metadata key", { metadata: { email: "admin@acme.example", extra: "x" } }],
    ["a removed metadata key", { metadata: {} }],
  ] as [string, Partial<AuditEventInput>][])("changes when %s changes", (_label, patch) => {
    const altered = { ...EVENT, ...patch };
    expect(computeAuditHash(altered, GENESIS_HASH)).not.toEqual(
      computeAuditHash(EVENT, GENESIS_HASH),
    );
  });

  // A null actor and an actor whose id is the empty string are different states, and the first is
  // normal for an unauthenticated caller.
  it("distinguishes a null field from an empty string", () => {
    const withNull = computeAuditHash({ ...EVENT, actorId: null }, GENESIS_HASH);
    const withEmpty = computeAuditHash({ ...EVENT, actorId: "" }, GENESIS_HASH);
    expect(withNull).not.toEqual(withEmpty);
  });
});

describe("canonicalAuditForm", () => {
  /**
   * Field assignment order must not matter. Two callers building the same event with keys written in a
   * different order have recorded the same evidence, and a hash that disagreed would report tampering
   * where there was none, which trains people to ignore the verifier.
   */
  it("ignores the order fields were assigned in", () => {
    const a: AuditEventInput = {
      action: "a",
      actorType: "user",
      actorId: null,
      resourceType: null,
      resourceId: null,
      traceId: null,
      sourceIp: null,
      occurredAt: "2026-07-30T09:00:00.000Z",
      metadata: { one: "1", two: "2" },
    };
    const b: AuditEventInput = {
      metadata: { two: "2", one: "1" },
      occurredAt: "2026-07-30T09:00:00.000Z",
      sourceIp: null,
      traceId: null,
      resourceId: null,
      resourceType: null,
      actorId: null,
      actorType: "user",
      action: "a",
    };
    expect(canonicalAuditForm(a)).toBe(canonicalAuditForm(b));
  });

  /**
   * THE AMBIGUITY THAT LENGTH PREFIXES EXIST TO REMOVE.
   *
   * With values merely joined by a separator, moving the separator between two adjacent fields
   * produces the same string, so two genuinely different events would share a hash and one could be
   * substituted for the other without detection. Prefixing each value with its byte length makes the
   * encoding injective.
   */
  it("cannot be confused by a value that contains the separator", () => {
    const first = { ...EVENT, actorId: "a", resourceType: "b:c" };
    const second = { ...EVENT, actorId: "a:b", resourceType: "c" };
    expect(canonicalAuditForm(first)).not.toBe(canonicalAuditForm(second));
    expect(computeAuditHash(first, GENESIS_HASH)).not.toEqual(
      computeAuditHash(second, GENESIS_HASH),
    );
  });

  it("cannot be confused by a metadata key that contains the separator", () => {
    const a = { ...EVENT, metadata: { "a:b": "c" } };
    const b = { ...EVENT, metadata: { a: "b:c" } };
    expect(canonicalAuditForm(a)).not.toBe(canonicalAuditForm(b));
  });

  // A newline in a value must not be able to forge an extra field, since fields are newline-joined.
  it("cannot be confused by a value containing a newline", () => {
    const injected = { ...EVENT, actorId: "x\naction:19:auth.login.failed" };
    expect(canonicalAuditForm(injected)).not.toBe(
      canonicalAuditForm({ ...EVENT, action: "auth.login.failed" }),
    );
  });

  it("is domain separated, so a digest cannot be replayed from another context", () => {
    expect(canonicalAuditForm(EVENT).startsWith("crbk.audit.v1\n")).toBe(true);
  });
});

describe("verifyAuditChain", () => {
  it("accepts an intact chain", () => {
    expect(verifyAuditChain(chain(25))).toBeNull();
  });

  it("accepts an empty chain, since a log with no events has nothing wrong with it", () => {
    expect(verifyAuditChain([])).toBeNull();
  });

  it("reports the first event when the chain does not start at genesis", () => {
    const events = chain(5).slice(1); // earliest event removed
    const broken = verifyAuditChain(events);
    expect(broken?.seq).toBe(2n);
    expect(broken?.reason).toMatch(/genesis/);
  });

  /**
   * An altered field is the case the whole structure exists for. The row's own hash no longer matches
   * its contents, and the verifier must name that row rather than the ones after it.
   */
  it("detects an altered field and names the row", () => {
    const events = chain(10);
    events[4] = { ...events[4], actorId: "99999999-9999-4999-8999-999999999999" };
    const broken = verifyAuditChain(events);
    expect(broken?.seq).toBe(5n);
    expect(broken?.reason).toMatch(/does not match the event's contents/);
  });

  it("detects a removed event in the middle", () => {
    const events = chain(10);
    events.splice(4, 1);
    const broken = verifyAuditChain(events);
    expect(broken?.seq).toBe(6n);
    expect(broken?.reason).toMatch(/removed or reordered/);
  });

  it("detects two events swapped", () => {
    const events = chain(10);
    [events[3], events[4]] = [events[4], events[3]];
    expect(verifyAuditChain(events)?.reason).toMatch(/removed or reordered/);
  });

  /**
   * The hardest case, and the one that says whether the chain is worth having: an attacker who alters
   * an event and RECOMPUTES its hash. That row now verifies on its own, so only the link from the next
   * event catches it. Without the chain, this edit would be undetectable.
   */
  it("detects an altered event whose own hash was recomputed to match", () => {
    const events = chain(10);
    const forgedInput = { ...events[4], actorId: "99999999-9999-4999-8999-999999999999" };
    events[4] = { ...forgedInput, hash: computeAuditHash(forgedInput, forgedInput.prevHash) };

    const broken = verifyAuditChain(events);
    expect(broken).not.toBeNull();
    // The altered row is now self-consistent, so the break surfaces at its SUCCESSOR.
    expect(broken?.seq).toBe(6n);
    expect(broken?.reason).toMatch(/removed or reordered/);
  });

  /**
   * Rewriting the whole tail is the limit of what a chain alone can detect, and being straight about
   * it matters more than the tests that pass. An attacker who can write to the table and recompute
   * every hash from the altered event to the head produces a chain that verifies perfectly.
   *
   * What stops that is not this function. It is that UPDATE and DELETE raise, that the privilege is
   * revoked, and ultimately that the head hash is copied somewhere the database cannot reach. This
   * test exists to record the limitation rather than to hide it.
   */
  it("cannot detect a full rewrite of the tail, which is why Postgres enforcement is the real control", () => {
    const events = chain(10);
    const altered: StoredAuditEvent[] = events.slice(0, 4);
    let prev = altered[3].hash;
    for (let i = 4; i < events.length; i += 1) {
      const input = { ...events[i], actorId: "99999999-9999-4999-8999-999999999999" };
      const hash = computeAuditHash(input, prev);
      altered.push({ ...input, prevHash: prev, hash });
      prev = hash;
    }
    expect(verifyAuditChain(altered)).toBeNull();

    // Anchoring against a head recorded elsewhere is what turns this back into a detection.
    expect(altered[altered.length - 1].hash).not.toEqual(events[events.length - 1].hash);
  });

  it("can verify a page of the chain given the hash it should follow", () => {
    const events = chain(10);
    const page = events.slice(5);
    expect(verifyAuditChain(page, events[4].hash)).toBeNull();
    expect(verifyAuditChain(page, GENESIS_HASH)).not.toBeNull();
  });
});
