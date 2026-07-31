import {
  GENESIS_HASH,
  computeAuditHash,
  type AuditEventInput,
  type AuditMetadata,
} from "@compliance-kit/crypto";

/**
 * Appends one event to a chain, in one transaction, so that concurrent appends cannot fork it.
 *
 * WHY THE ORDER OF THE THREE STEPS IS THE WHOLE THING.
 *
 * Appending means read the current head, hash the new event onto it, insert. That is a
 * read-modify-write, so two callers that both read head H both produce an event whose `prev_hash` is H,
 * and the chain forks into two histories that each verify perfectly on their own. Nothing later can
 * tell you which one is real.
 *
 * `pg_advisory_xact_lock` is taken FIRST, before the head is read, and that is not interchangeable with
 * taking it after. A lock acquired after the read protects nothing: the value it was meant to protect
 * has already been observed. Because it is the `_xact_` variant it is released when the transaction
 * ends, including on rollback, so a failed append cannot leave the chain locked.
 *
 * `UNIQUE(prev_hash)` in the schema is the second line of defence and stays there deliberately. If this
 * lock is ever removed, mis-keyed, or bypassed by another code path, the database refuses the second
 * insert rather than accepting a fork. Belt and braces, because a fork is the one failure the chain
 * cannot detect afterwards.
 */

/**
 * Lock key for the audit chain. Any stable number works; what matters is that every appender in every
 * process uses the SAME one, so it is defined here rather than passed in.
 *
 * Advisory locks share one 64-bit keyspace across the whole database, so a collision with another
 * subsystem's key would serialise two unrelated things against each other. This value is the ASCII of
 * "crbkAUDT" read as an integer, which makes an accidental collision with a hand-picked small number
 * or another component's hash unlikely, and makes the source of the constant obvious to whoever finds
 * it in `pg_locks`.
 */
const AUDIT_CHAIN_LOCK_KEY = 0x6372626b41554454n;

/**
 * The narrow slice of a Prisma client this writer needs.
 *
 * Declared structurally rather than importing a client type, because the master and tenant clients are
 * SEPARATELY GENERATED types that happen to have the same shape. Importing one would make this writer
 * usable with only that database; a cast would make it accept either and also accept anything else,
 * including the wrong client for the current tenant. An interface accepts both honestly and still
 * rejects an object that cannot do the job.
 *
 * Raw SQL rather than the generated model methods, for the same reason: `auditEvent.create` exists on
 * two unrelated types, whereas `$queryRawUnsafe` is identical on both, and this code needs
 * `pg_advisory_xact_lock` and `now()` from the server anyway.
 */
export interface AuditChainClient {
  $transaction<T>(fn: (tx: AuditChainTransaction) => Promise<T>): Promise<T>;
}

export interface AuditChainTransaction {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
  /**
   * Used for the lock, because `pg_advisory_xact_lock` returns `void` and Prisma's query path tries to
   * deserialize every column: `$queryRawUnsafe` fails with "Failed to deserialize column of type
   * 'void'". The execute path expects no result set, which is what this statement produces.
   */
  $executeRawUnsafe(query: string, ...values: unknown[]): Promise<number>;
}

/** What the caller supplies. Everything the database decides is filled in here. */
export interface AppendAuditEvent {
  action: string;
  actorType: "user" | "control_plane" | "system" | "anonymous";
  actorId?: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  traceId?: string | null;
  sourceIp?: string | null;
  metadata?: AuditMetadata;
}

export interface AppendedAuditEvent {
  seq: bigint;
  occurredAt: string;
  hash: Buffer;
  prevHash: Buffer;
}

interface HeadRow {
  now_at: Date;
  prev_hash: Buffer | Uint8Array | null;
}

/**
 * Append one event and return what was stored.
 *
 * Deliberately NOT swallowing errors. Everywhere else in this kit a non-critical failure is logged and
 * the request continues, but an audit append that silently failed would leave the service claiming to
 * record evidence it did not record, which is worse than the request failing. The caller decides
 * whether a given action may proceed without its audit record; see the call sites.
 */
export async function appendAuditEvent(
  client: AuditChainClient,
  event: AppendAuditEvent,
): Promise<AppendedAuditEvent> {
  return client.$transaction(async (tx) => {
    // FIRST. See the module comment: after the read this would protect nothing.
    await tx.$executeRawUnsafe("SELECT pg_advisory_xact_lock($1)", AUDIT_CHAIN_LOCK_KEY);

    /**
     * The timestamp comes from the DATABASE, in the same round trip as the head.
     *
     * Two reasons, and the second is the one that bites. It has to be known here because it is part of
     * the hash, so a column default of `now()` would mean hashing a value the database had not yet
     * chosen. And taking it from the appending process instead would put every instance's clock into the
     * evidence: two machines a second apart would write events whose recorded order contradicted their
     * chain order, and NTP drift on one box would silently skew a whole tenant's timeline.
     *
     * `now()` is transaction start time, so it is stable for the whole append rather than shifting
     * between the read and the insert.
     */
    const rows = await tx.$queryRawUnsafe<HeadRow[]>(
      `SELECT now() AS now_at,
              (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1) AS prev_hash`,
    );
    const row = rows[0];
    if (!row) throw new Error("audit append could not read the chain head");

    // Genesis when the table is empty. A fixed value rather than NULL, so UNIQUE(prev_hash) also
    // prevents a second first-event; see GENESIS_HASH.
    const prevHash = row.prev_hash === null ? GENESIS_HASH : Buffer.from(row.prev_hash);

    const input: AuditEventInput = {
      action: event.action,
      actorType: event.actorType,
      actorId: event.actorId ?? null,
      resourceType: event.resourceType ?? null,
      resourceId: event.resourceId ?? null,
      traceId: event.traceId ?? null,
      sourceIp: event.sourceIp ?? null,
      // The exact string that is hashed is the exact string stored, with no reliance on how a driver
      // renders a timestamp on the way back out.
      occurredAt: row.now_at.toISOString(),
      metadata: event.metadata ?? {},
    };

    const hash = computeAuditHash(input, prevHash);

    const inserted = await tx.$queryRawUnsafe<{ seq: bigint }[]>(
      `INSERT INTO audit_events
         (occurred_at, action, actor_type, actor_id, resource_type, resource_id,
          trace_id, source_ip, metadata, prev_hash, hash)
       VALUES ($1::timestamptz, $2, $3::audit_actor_type, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
       RETURNING seq`,
      input.occurredAt,
      input.action,
      input.actorType,
      input.actorId,
      input.resourceType,
      input.resourceId,
      input.traceId,
      input.sourceIp,
      JSON.stringify(input.metadata),
      prevHash,
      hash,
    );

    const seq = inserted[0]?.seq;
    if (seq === undefined) throw new Error("audit append inserted no row");

    return { seq, occurredAt: input.occurredAt, hash, prevHash };
  });
}
