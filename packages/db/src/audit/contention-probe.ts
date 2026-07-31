/**
 * Prove the audit chain does not fork under concurrent appends.
 *
 * A unit test with a mocked client can assert that the writer calls `pg_advisory_xact_lock` before it
 * reads the head. It cannot tell you whether the lock actually serialises anything, because that
 * depends on Postgres, on every caller using the same key, and on the read and the insert sharing one
 * transaction. Only real contention settles it.
 *
 * WHAT COUNTS AS A PASS, and why it is not merely "no errors".
 *
 * `UNIQUE(prev_hash)` is the schema's fork guard, so if the lock is doing its job that constraint NEVER
 * fires. A run where appends failed with a unique violation and were retried would look healthy while
 * proving the opposite: that the lock did not serialise and the database caught what the application
 * should have prevented. So a single unique violation fails this probe.
 *
 * Lives in packages/db rather than scripts/ because `pg` resolves from this package, and because the
 * other operator CLIs live here too.
 *
 * Usage: node packages/db/dist/audit/contention-probe.js [--appends 50]
 */
import { existsSync } from "node:fs";
import path from "node:path";
import { config as readDotenvFile } from "dotenv";
import { Client } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import { GENESIS_HASH, computeAuditHash } from "@compliance-kit/crypto";
import { PrismaClient } from "../generated/master/client";
import { appendAuditEvent, type AuditChainClient } from "./audit-writer";

function loadLocalDotenv(): void {
  if (process.env.NODE_ENV === "production") return;
  let dir = process.cwd();
  for (let level = 0; level < 5; level += 1) {
    const candidate = path.join(dir, ".env");
    if (existsSync(candidate)) {
      readDotenvFile({ path: candidate, quiet: true });
      return;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return;
    dir = parent;
  }
}

interface EventRow {
  seq: string;
  occurred_at: Date;
  action: string;
  actor_type: string;
  actor_id: string | null;
  resource_type: string | null;
  resource_id: string | null;
  trace_id: string | null;
  source_ip: string | null;
  metadata: Record<string, string>;
  prev_hash: Buffer;
  hash: Buffer;
}

async function main(): Promise<void> {
  loadLocalDotenv();
  const argIndex = process.argv.indexOf("--appends");
  const appends = Number(argIndex !== -1 ? (process.argv[argIndex + 1] ?? "50") : "50");

  const url = process.env.MASTER_DATABASE_URL;
  if (!url) {
    process.stderr.write("MASTER_DATABASE_URL must be set\n");
    process.exitCode = 1;
    return;
  }

  let failures = 0;
  const fail = (m: string): void => {
    process.stderr.write(`  FAIL  ${m}\n`);
    failures += 1;
  };
  const pass = (m: string): void => {
    process.stdout.write(`  PASS  ${m}\n`);
  };

  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });
  // A plain client for reading back, because the probe cannot clean up after itself: the table is
  // append-only and the triggers refuse DELETE even for a superuser. It records where it started and
  // verifies only its own rows instead.
  const admin = new Client({ connectionString: url });

  try {
    await admin.connect();
    const before = await admin.query<{ seq: string }>(
      "SELECT COALESCE(MAX(seq), 0)::text AS seq FROM audit_events",
    );
    const startSeq = BigInt(before.rows[0]?.seq ?? "0");
    process.stdout.write(`Firing ${appends} concurrent appends from seq ${startSeq}\n`);

    const results = await Promise.allSettled(
      Array.from({ length: appends }, (_, i) =>
        appendAuditEvent(prisma as unknown as AuditChainClient, {
          action: "probe.concurrent",
          actorType: "system",
          actorId: `probe-${i}`,
          metadata: { index: String(i) },
        }),
      ),
    );

    const rejected = results.filter((r) => r.status === "rejected");
    const isUnique = (r: PromiseRejectedResult): boolean => {
      const msg = r.reason instanceof Error ? r.reason.message : String(r.reason);
      return (
        msg.includes("audit_events_prev_hash_unique") || msg.includes("audit_events_hash_unique")
      );
    };
    const uniqueViolations = rejected.filter(isUnique);

    // THE assertion. A unique violation means the lock did not serialise and the database caught a fork
    // the application should have made impossible.
    if (uniqueViolations.length === 0) {
      pass(
        `no unique violations across ${appends} concurrent appends, so the lock serialised them`,
      );
    } else {
      const first = uniqueViolations[0];
      const msg = first.reason instanceof Error ? first.reason.message : String(first.reason);
      fail(
        `${uniqueViolations.length} unique violation(s): the lock did NOT serialise. ${msg.slice(0, 160)}`,
      );
    }

    const others = rejected.filter((r) => !isUnique(r));
    if (others.length === 0) {
      pass(`all ${appends} appends succeeded`);
    } else {
      const msg =
        others[0].reason instanceof Error ? others[0].reason.message : String(others[0].reason);
      fail(`${others.length} append(s) failed for another reason: ${msg.slice(0, 200)}`);
    }

    /**
     * `ORDER BY audit_events.seq`, qualified, and no `::text` alias on the selected column.
     *
     * This cost an hour. The first version selected `seq::text AS seq` and ordered by `seq`, and
     * PostgreSQL resolves an unqualified ORDER BY name against the OUTPUT columns first, so it sorted
     * the TEXT: 1, 10, 11 ... 19, 2, 20. The second row returned was seq 10, its prev_hash did not match
     * row 1's hash, and the probe reported "chain link broken at seq 10" against a chain that was
     * perfectly intact.
     *
     * Worth recording because of how convincingly it lied. It reproduced every run, pointed at a
     * specific row, and implicated the concurrency code, which is exactly where suspicion naturally
     * falls. It also hid whenever every seq had the same number of digits, so a 20-append run onto an
     * existing chain of 50 passed cleanly. What settled it was asking Postgres directly whether any row
     * disagreed with its predecessor, and getting zero.
     *
     * bigint comes back as a string from node-postgres regardless, so the cast bought nothing.
     */
    const rows = await admin.query<EventRow>(
      `SELECT seq, occurred_at, action, actor_type, actor_id, resource_type, resource_id,
              trace_id, source_ip, metadata, prev_hash, hash
         FROM audit_events WHERE seq > $1 ORDER BY audit_events.seq ASC`,
      [startSeq.toString()],
    );

    if (rows.rowCount === appends) {
      pass(`exactly ${appends} rows landed, so none was lost or duplicated`);
    } else {
      fail(`expected ${appends} rows, found ${String(rows.rowCount)}`);
    }

    let expectedPrev: Buffer = GENESIS_HASH;
    if (startSeq !== 0n) {
      const head = await admin.query<{ hash: Buffer }>(
        "SELECT hash FROM audit_events WHERE seq = $1",
        [startSeq.toString()],
      );
      expectedPrev = Buffer.from(head.rows[0].hash);
    }

    let linkBreak: string | null = null;
    let hashBreak: string | null = null;
    // Counted, so the pass line can say how many were actually checked. The first version reported
    // "all 50 hashes recompute" after breaking out of the loop at row 10, having checked nine.
    let checked = 0;
    for (const r of rows.rows) {
      if (!Buffer.from(r.prev_hash).equals(expectedPrev)) {
        linkBreak = r.seq;
        break;
      }
      /**
       * Recomputed from what the DATABASE returned, not from what the writer sent. That is what catches
       * a round-trip mismatch: a timestamp rendered differently on the way out, or metadata normalised
       * by jsonb. Either would present as tampering later, so it is worth catching here.
       */
      const recomputed = computeAuditHash(
        {
          action: r.action,
          actorType: r.actor_type,
          actorId: r.actor_id,
          resourceType: r.resource_type,
          resourceId: r.resource_id,
          traceId: r.trace_id,
          sourceIp: r.source_ip,
          occurredAt: r.occurred_at.toISOString(),
          metadata: r.metadata,
        },
        Buffer.from(r.prev_hash),
      );
      if (!recomputed.equals(Buffer.from(r.hash))) {
        hashBreak = r.seq;
        break;
      }
      expectedPrev = Buffer.from(r.hash);
      checked += 1;
    }

    /**
     * Refuse to report a pass on an empty result set.
     *
     * The first version of this probe did exactly that: when every append failed, no rows came back, the
     * two loops below never ran, and both checks printed PASS. A probe that reports success precisely
     * when nothing happened is worse than no probe, because it is trusted. The same vacuous-pass trap
     * the slowloris probe had.
     */
    if (rows.rowCount === 0) {
      fail("no rows to verify, so the chain and hash checks proved nothing (not a pass)");
    } else if (linkBreak === null) {
      pass(`all ${String(checked)} events point at their predecessor: one unbroken chain, no fork`);
    } else {
      fail(`chain link broken at seq ${linkBreak}`);
    }

    if (rows.rowCount === 0) {
      // Already reported above; do not print a second misleading line.
    } else if (hashBreak === null) {
      pass(
        `all ${String(checked)} hashes recompute from what Postgres returned: the round trip is exact`,
      );
    } else {
      fail(`hash mismatch at seq ${hashBreak}: the stored row does not hash to its stored hash`);
    }
  } finally {
    await prisma.$disconnect().catch(() => undefined);
    await admin.end().catch(() => undefined);
  }

  if (failures > 0) {
    process.stderr.write(`\n${failures} check(s) failed.\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write("\nAll checks passed.\n");
}

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
