/**
 * Walk an audit chain and report whether it holds.
 *
 * A chain nobody walks is a column of hashes, not a control. The triggers make the log append-only and
 * the hashes make an edit that got past them detectable, but "detectable" is a claim about a check that
 * somebody actually runs. This is that check, and it is why COMPLIANCE.md can say tamper-EVIDENT rather
 * than tamper-proof.
 *
 * Reuses `verifyAuditChain` from packages/crypto, the same function the unit tests exercise, rather than
 * reimplementing the walk. A second implementation would eventually disagree with the writer's, and
 * then this tool would either clear a broken chain or condemn a sound one.
 *
 * PAGED, because a chain grows without bound and an audit log is the last thing that should need to fit
 * in memory to be checkable. `verifyAuditChain` takes the hash the first supplied event should point at,
 * so each page carries the previous page's head forward and the seam between pages is verified like any
 * other link.
 *
 * Usage:
 *   pnpm audit:verify --master
 *   pnpm audit:verify --tenant acme
 *   pnpm audit:verify --tenant acme --page-size 5000
 *
 * Exits 0 if the chain holds, 1 if it does not or if the arguments are wrong.
 */
import { existsSync } from "node:fs";
import path from "node:path";
import { config as readDotenvFile } from "dotenv";
import { GENESIS_HASH, verifyAuditChain, type StoredAuditEvent } from "@compliance-kit/crypto";
import { ConnectionManager } from "../connection-manager";

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

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const [flag, inline] = arg.slice(2).split("=", 2);
    // A bare flag like --master takes the value "true" rather than swallowing the next argument.
    const next = argv[i + 1];
    if (inline !== undefined) out[flag] = inline;
    else if (next !== undefined && !next.startsWith("--")) out[flag] = argv[++i];
    else out[flag] = "true";
  }
  return out;
}

/** One row as the database returns it. */
interface Row {
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

/**
 * The one method this needs, declared structurally so BOTH generated clients satisfy it.
 *
 * No cast at the call sites, deliberately: eslint flagged one as unnecessary, which is the useful
 * signal that the master and tenant clients genuinely conform rather than being forced to. A cast here
 * would also have accepted an object that cannot page, and the failure would surface at runtime.
 */
interface PagedClient {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
}

const USAGE = `
Verify an append-only audit chain.

  pnpm audit:verify --master              the control-plane chain
  pnpm audit:verify --tenant <slug|uuid>  one tenant's chain
  pnpm audit:verify --tenant X --page-size 5000

Environment: MASTER_DATABASE_URL, TENANT_CLUSTER_URL
`;

/**
 * Read one page, ordered by seq.
 *
 * `ORDER BY audit_events.seq` is QUALIFIED on purpose. An unqualified name is resolved against the
 * output columns first, so selecting a cast or aliased `seq` and ordering by it sorts the alias rather
 * than the column. That produced a lexicographic walk (1, 10, 11, 2) in the contention probe and a
 * confident, reproducible report of a broken chain that was perfectly sound. Qualifying it removes the
 * ambiguity entirely.
 */
async function readPage(client: PagedClient, afterSeq: bigint, limit: number): Promise<Row[]> {
  return client.$queryRawUnsafe<Row[]>(
    `SELECT seq, occurred_at, action, actor_type, actor_id, resource_type, resource_id,
            trace_id, source_ip, metadata, prev_hash, hash
       FROM audit_events
      WHERE seq > $1
      ORDER BY audit_events.seq ASC
      LIMIT $2`,
    afterSeq.toString(),
    limit,
  );
}

function toStored(r: Row): StoredAuditEvent {
  return {
    seq: BigInt(r.seq),
    // Re-derived from what the database returned, not from what was written. That is the point: a
    // mismatch between the two IS the finding, whether it came from tampering or from a round trip
    // that does not preserve a value.
    occurredAt: r.occurred_at.toISOString(),
    action: r.action,
    actorType: r.actor_type,
    actorId: r.actor_id,
    resourceType: r.resource_type,
    resourceId: r.resource_id,
    traceId: r.trace_id,
    sourceIp: r.source_ip,
    metadata: r.metadata,
    prevHash: Buffer.from(r.prev_hash),
    hash: Buffer.from(r.hash),
  };
}

async function main(): Promise<void> {
  loadLocalDotenv();
  const args = parseArgs(process.argv.slice(2));

  const masterUrl = process.env.MASTER_DATABASE_URL;
  const tenantClusterUrl = process.env.TENANT_CLUSTER_URL ?? masterUrl;
  if (!masterUrl || !tenantClusterUrl) {
    process.stderr.write(`MASTER_DATABASE_URL and TENANT_CLUSTER_URL must be set.\n${USAGE}`);
    process.exitCode = 1;
    return;
  }

  const wantsMaster = args.master === "true";
  const tenant = args.tenant;
  // Requiring one of the two, rather than defaulting to master, because "verify passed" against the
  // wrong database is the most misleading output this tool could produce.
  if (wantsMaster === Boolean(tenant)) {
    process.stderr.write(`Specify exactly one of --master or --tenant <slug|uuid>.\n${USAGE}`);
    process.exitCode = 1;
    return;
  }

  const pageSize = Number(args["page-size"] ?? "1000");
  if (!Number.isInteger(pageSize) || pageSize < 1) {
    process.stderr.write(`--page-size must be a positive integer.\n`);
    process.exitCode = 1;
    return;
  }

  const cm = new ConnectionManager({
    masterUrl,
    tenantClusterUrl,
    onPoolError: (err, db) => process.stderr.write(`pool error on ${db}: ${err.message}\n`),
  });

  try {
    let client: PagedClient;
    let label: string;
    if (wantsMaster) {
      client = cm.master;
      label = "master (control-plane chain)";
    } else {
      const resolved = await cm.resolveTenant(tenant);
      client = cm.getTenantDb(resolved);
      label = `tenant ${resolved.slug} (${resolved.databaseName})`;
    }

    process.stdout.write(`Verifying ${label}\n`);

    let afterSeq = 0n;
    let expectedPrev: Buffer = GENESIS_HASH;
    let total = 0;
    let headHash: Buffer | null = null;

    for (;;) {
      const rows = await readPage(client, afterSeq, pageSize);
      if (rows.length === 0) break;

      const events = rows.map(toStored);
      const broken = verifyAuditChain(events, expectedPrev);
      if (broken) {
        /**
         * Count the events verified INSIDE this page as well as the pages before it.
         *
         * Without this the message read "Verified 0 event(s) before the break" whenever the break fell
         * in the first page, because `total` only advances once a whole page passes. With the default
         * page size that is the usual case, so the number was almost always wrong and always wrong in
         * the same direction: understating how much of the log is trustworthy, which is exactly the
         * judgement someone reads this output to make.
         */
        const indexOfBreak = events.findIndex((e) => e.seq === broken.seq);
        const verifiedBefore = total + (indexOfBreak === -1 ? 0 : indexOfBreak);
        process.stderr.write(
          `\n  BROKEN at seq ${broken.seq.toString()}\n` +
            `  ${broken.reason}\n` +
            (broken.expected ? `  expected: ${broken.expected}\n` : "") +
            (broken.actual ? `  actual:   ${broken.actual}\n` : "") +
            `\nVerified ${verifiedBefore} event(s) before the break, so the log is trustworthy up to ` +
            `seq ${(broken.seq - 1n).toString()}. Everything from the break onward is unverifiable, ` +
            `because each hash depends on the one before it.\n`,
        );
        process.exitCode = 1;
        return;
      }

      total += events.length;
      const last = events[events.length - 1];
      expectedPrev = last.hash;
      headHash = last.hash;
      afterSeq = last.seq;

      // Only report progress on a chain long enough for the wait to be noticeable.
      if (total % (pageSize * 10) === 0) process.stdout.write(`  ...${total} events\n`);
    }

    if (total === 0) {
      // Not a pass and not a failure. An empty chain is the correct state for a database that has
      // recorded nothing yet, and saying "verified" would imply evidence that does not exist.
      process.stdout.write(`\n  EMPTY: no events recorded yet. Nothing to verify.\n`);
      return;
    }

    process.stdout.write(
      `\n  OK: ${total} event(s), chain intact from genesis to head.\n` +
        `  head hash: ${headHash?.toString("hex") ?? "(none)"}\n\n` +
        `  Record that head hash somewhere this database cannot reach.\n` +
        `  A chain verifies against itself, so an attacker who can write to the table and recompute\n` +
        `  every hash from their edit to the head produces a chain that passes this check. Comparing\n` +
        `  the head against a value stored elsewhere is what closes that gap; nothing inside the\n` +
        `  database can.\n`,
    );
  } finally {
    await cm.close();
  }
}

export { readPage, toStored };

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
