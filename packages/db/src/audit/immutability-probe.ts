/**
 * Prove that `audit_events` is append-only, by trying to violate it.
 *
 * The three layers in `sql/audit-immutability.sql` were verified by hand on 2026-07-30 and never turned
 * into a check, which left the audit log's CENTRAL claim as the one claim with no runnable evidence.
 * COMPLIANCE.md says "append-only", `pnpm audit:verify` proves the chain is internally consistent, and
 * nothing at all proved that the database refuses a modification. This closes that.
 *
 * EVERY DESTRUCTIVE ATTEMPT RUNS INSIDE A TRANSACTION THAT IS ROLLED BACK, and that is not defensive
 * habit, it is the difference between a probe and an incident. If a trigger has been dropped, then
 * `TRUNCATE audit_events` is exactly the one-statement erasure of the audit log that the trigger exists
 * to prevent, and a probe that executed it would destroy the evidence it was asked to check, in the
 * situation where that evidence matters most. TRUNCATE is transactional in Postgres, so a ROLLBACK
 * genuinely undoes it. The probe therefore reports the missing control instead of demonstrating it.
 *
 * WHY A NON-EMPTY CHAIN IS A PRECONDITION AND NOT A NICETY. `UPDATE` and `DELETE` triggers are FOR EACH
 * ROW, so against an empty table they never fire: both statements succeed, having matched nothing, and a
 * probe that treated "no error" as "refused" would print two passes on a table with no protection at
 * all. The vacuous-pass trap that the slowloris probe and the contention probe each shipped with once,
 * so this one refuses to run rather than reporting on nothing. (`TRUNCATE` is a statement trigger and
 * does fire on an empty table, which is why only two of the three are affected.)
 *
 * Lives in packages/db for the reason contention-probe.ts gives: `pg` resolves from this package and the
 * operator CLIs live here. Uses `pg` directly rather than `docker exec psql` the way
 * scripts/clean-test-tenants.sh does, because CI's Postgres is a service container with no predictable
 * container name, and a probe that only runs on a laptop is not evidence anyone else can reproduce.
 *
 * Usage:
 *   pnpm audit:immutability --master
 *   pnpm audit:immutability --tenant acme
 */
import { randomBytes } from "node:crypto";
import { Client } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import { ConnectionManager } from "../connection-manager";
import { PrismaClient } from "../generated/master/client";
import { appendAuditEvent } from "./audit-writer";
import { loadLocalDotenv } from "../cli/load-dotenv";

/**
 * A bare flag yields the BOOLEAN `true`, not the string "true", so a flag that needs a value can say so
 * immediately rather than going off to resolve a tenant literally named "true".
 *
 * STILL LOCAL, unlike `loadLocalDotenv` which was extracted to ../cli/load-dotenv. The difference is that
 * the six copies of that were byte-identical, so collapsing them was a pure move, whereas the four copies
 * of this one are NOT: verify-chain and this file return `Record<string, string | true>`, while
 * seed-tenant-admin and manage-keys return `Record<string, string>` and therefore treat a bare flag as
 * absent. Unifying them would change how two operator CLIs read their arguments, which is a behaviour
 * change that belongs in its own commit rather than riding along in a documentation pass.
 */
function parseArgs(argv: string[]): Record<string, string | true> {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const [flag, inline] = arg.slice(2).split("=", 2);
    const next = argv[i + 1];
    if (inline !== undefined) out[flag] = inline;
    else if (next !== undefined && !next.startsWith("--")) out[flag] = argv[++i];
    else out[flag] = true;
  }
  return out;
}

const USAGE = `
Prove audit_events refuses modification, by attempting it.

  pnpm audit:immutability --master              the control-plane chain
  pnpm audit:immutability --tenant <slug|uuid>  one tenant's chain

Every attempt is rolled back, so this is safe to run against a live chain.

Environment:
  MASTER_DATABASE_URL   required
  TENANT_CLUSTER_URL    optional; defaults to MASTER_DATABASE_URL, which is correct when the
                        tenant databases live on the same cluster as the master
`;

/** The trigger raises `restrict_violation`, which is SQLSTATE 23001. */
const RESTRICT_VIOLATION = "23001";

interface PgError {
  code?: string;
  message: string;
}

function asPgError(err: unknown): PgError {
  if (err instanceof Error) {
    return { code: (err as Error & { code?: string }).code, message: err.message };
  }
  return { message: String(err) };
}

/** Snapshot of the state the refusals must leave untouched. */
interface ChainState {
  count: bigint;
  headHash: string | null;
}

async function readState(client: Client): Promise<ChainState> {
  const res = await client.query<{ count: string; head: string | null }>(
    `SELECT count(*)::text AS count,
            (SELECT encode(hash, 'hex') FROM audit_events ORDER BY seq DESC LIMIT 1) AS head
       FROM audit_events`,
  );
  const row = res.rows[0];
  return { count: BigInt(row?.count ?? "0"), headHash: row?.head ?? null };
}

/**
 * Is the row that was the head when the probe started still present?
 *
 * Asked by hash rather than by seq, because the question is whether that exact event survived. A row
 * whose contents were altered hashes differently, so a matching hash means the row is both present and
 * unmodified, which is precisely the invariant the destructive attempts must not have broken.
 */
async function headStillPresent(client: Client, headHashHex: string): Promise<boolean> {
  const res = await client.query<{ present: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM audit_events WHERE hash = decode($1, 'hex')) AS present`,
    [headHashHex],
  );
  return res.rows[0]?.present === true;
}

async function main(): Promise<void> {
  loadLocalDotenv();
  const args = parseArgs(process.argv.slice(2));

  const masterUrl = process.env.MASTER_DATABASE_URL;
  if (!masterUrl) {
    process.stderr.write(`MASTER_DATABASE_URL must be set.\n${USAGE}`);
    process.exitCode = 1;
    return;
  }
  const tenantClusterUrl = process.env.TENANT_CLUSTER_URL ?? masterUrl;

  const wantsMaster = args.master === true || args.master === "true";
  if (args.tenant === true) {
    process.stderr.write(`--tenant needs a slug or uuid.\n${USAGE}`);
    process.exitCode = 1;
    return;
  }
  const tenant = args.tenant;
  // Requiring one of the two rather than defaulting, because "immutability verified" against a database
  // the operator did not mean to check is the most misleading thing this tool could print.
  if (wantsMaster === Boolean(tenant)) {
    process.stderr.write(`Specify exactly one of --master or --tenant <slug|uuid>.\n${USAGE}`);
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

  // Resolving a tenant needs the registry in the master, so the manager is built either way.
  const cm = new ConnectionManager({
    masterUrl,
    tenantClusterUrl,
    onPoolError: (err, db) => process.stderr.write(`pool error on ${db}: ${err.message}\n`),
  });

  let targetUrl: string;
  let label: string;
  try {
    if (wantsMaster) {
      targetUrl = masterUrl;
      label = "master (control-plane chain)";
    } else {
      const resolved = await cm.resolveTenant(tenant);
      // Built here rather than borrowed from the manager, whose tenantConnectionString is private, and
      // deliberately so: the probe needs a plain client it can BEGIN and ROLLBACK on, which is not
      // something the pooled Prisma clients are for.
      const url = new URL(tenantClusterUrl);
      url.pathname = `/${resolved.databaseName}`;
      targetUrl = url.toString();
      label = `tenant ${resolved.slug} (${resolved.databaseName})`;
    }
  } finally {
    await cm.close().catch(() => undefined);
  }

  process.stdout.write(`Probing append-only enforcement on ${label}\n`);

  const client = new Client({ connectionString: targetUrl });
  await client.connect();

  try {
    const before = await readState(client);

    /**
     * PRECONDITION. See the module comment: with no rows, the UPDATE and DELETE triggers never fire and
     * both checks would pass against a table with no protection whatsoever. Exiting non-zero rather than
     * skipping, because a probe that quietly proves nothing is the failure mode being guarded against.
     */
    if (before.count === 0n) {
      fail(
        "the chain is EMPTY, so the row triggers cannot fire and this probe would prove nothing. " +
          "Run `pnpm smoke` or provision a tenant first, then re-run.",
      );
      process.exitCode = 1;
      return;
    }
    pass(
      `chain has ${String(before.count)} event(s), so the row triggers have something to fire on`,
    );

    /**
     * Each attempt in its own transaction, rolled back whatever happens.
     *
     * Two jobs. It keeps a missing trigger from actually mutating or erasing the log, and it isolates the
     * attempts from each other: the raised exception aborts the transaction, so without the explicit
     * boundary the next statement would fail with "current transaction is aborted" and be reported as a
     * refusal it never earned.
     */
    const attempt = async (label: string, sql: string, op: string): Promise<void> => {
      await client.query("BEGIN");
      try {
        await client.query(sql);
        // Reached only if nothing refused it. The ROLLBACK in `finally` undoes the damage.
        fail(
          `${label} SUCCEEDED. ${op} on audit_events is not being refused, so the append-only claim ` +
            `in COMPLIANCE.md is false for this database. Check the triggers from ` +
            `sql/audit-immutability.sql are present and enabled.`,
        );
      } catch (err) {
        const { code, message } = asPgError(err);
        // The SQLSTATE is asserted, not just the fact of an error. Any statement can fail for unrelated
        // reasons (a missing column, a permission problem, a syntax error), and every one of those would
        // otherwise read as proof of a control that might not exist.
        if (code === RESTRICT_VIOLATION && message.includes("append-only")) {
          pass(`${label} refused by the trigger (SQLSTATE ${code})`);
        } else if (code === "42501") {
          // The REVOKE layer answered first. Also a refusal, and worth naming distinctly: it means the
          // connecting role is not the owner, which is the deployment posture the SQL is written for.
          pass(`${label} refused by table privileges (SQLSTATE 42501, the REVOKE layer)`);
        } else {
          fail(
            `${label} failed, but not as a refusal: SQLSTATE ${code ?? "none"} ${message.slice(0, 200)}`,
          );
        }
      } finally {
        await client.query("ROLLBACK");
      }
    };

    // Targets the lowest seq specifically. `WHERE true` would work, but naming one row keeps the
    // statement's effect small in the case where nothing refuses it.
    await attempt(
      "UPDATE of an existing event",
      `UPDATE audit_events SET action = action || '.tampered'
        WHERE seq = (SELECT min(seq) FROM audit_events)`,
      "UPDATE",
    );

    await attempt(
      "DELETE of an existing event",
      `DELETE FROM audit_events WHERE seq = (SELECT min(seq) FROM audit_events)`,
      "DELETE",
    );

    /**
     * The layer that exists because row triggers do NOT fire for TRUNCATE. Without the statement trigger
     * this is a one-statement erasure of the entire log, so it is also the attempt for which the
     * surrounding ROLLBACK matters most.
     */
    await attempt("TRUNCATE of the whole table", `TRUNCATE audit_events`, "TRUNCATE");

    /**
     * The fork guard, direct rather than under contention. `pnpm audit:contention` proves the advisory
     * lock serialises concurrent appends; this proves the constraint behind it would still refuse a fork
     * if the lock were removed, which is the reason for having both.
     *
     * A random 32-byte hash so the width CHECK passes and the UNIQUE on prev_hash is what refuses it.
     * Otherwise the row would be rejected for the wrong reason and the check would prove nothing.
     */
    await client.query("BEGIN");
    try {
      const existingPrev = await client.query<{ prev_hash: Buffer }>(
        "SELECT prev_hash FROM audit_events ORDER BY seq DESC LIMIT 1",
      );
      const prev = existingPrev.rows[0]?.prev_hash;
      if (!prev) {
        fail("could not read a prev_hash to duplicate, so the fork guard was not exercised");
      } else {
        await client.query(
          `INSERT INTO audit_events
             (occurred_at, action, actor_type, actor_id, resource_type, resource_id,
              trace_id, source_ip, metadata, prev_hash, hash)
           VALUES (now(), 'probe.fork', 'system', NULL, NULL, NULL, NULL, NULL, '{}'::jsonb, $1, $2)`,
          [prev, randomBytes(32)],
        );
        fail(
          "a second event claiming an already-used prev_hash was ACCEPTED: the chain can fork, " +
            "which is the one tampering the hash chain cannot detect afterwards",
        );
      }
    } catch (err) {
      const { code, message } = asPgError(err);
      // 23505 is unique_violation.
      if (code === "23505" && message.includes("prev_hash")) {
        pass(
          "a duplicate prev_hash is refused by UNIQUE, so the chain cannot fork (SQLSTATE 23505)",
        );
      } else {
        fail(
          `the fork attempt failed for another reason: SQLSTATE ${code ?? "none"} ${message.slice(0, 200)}`,
        );
      }
    } finally {
      await client.query("ROLLBACK");
    }

    /**
     * Nothing above DESTROYED anything.
     *
     * The triggers are BEFORE triggers, so a refused statement is never performed rather than performed
     * and undone, and this is what confirms that rather than assuming it. It also catches an attempt that
     * partially succeeded before something else objected.
     *
     * GROWTH IS NOT A FAILURE, and an earlier version of this check got that wrong. It required the count
     * and the head hash to be IDENTICAL before and after, which turns any legitimate concurrent append
     * into a false FAIL announcing that the chain changed during the probe. That directly contradicted
     * this tool's own usage text promising it is safe to run against a live chain, and "live" is exactly
     * when another writer exists: a single login lands an event. The same mistake the contention probe
     * shipped with, where an exact row count asserted a quiescent database that CI does not provide.
     *
     * So the invariant is narrowed to what the destructive attempts could actually have broken:
     *
     *   1. The chain did not SHRINK. A successful DELETE or TRUNCATE reduces the count; nothing else does,
     *      because the table refuses UPDATE and the writer only appends.
     *   2. The row that was the head at the start is STILL THERE, matched by hash. A DELETE would remove
     *      it and an UPDATE would change what it hashes to, so its survival rules out both against the
     *      specific row the attempts targeted.
     *
     * Note the attempts deliberately target `min(seq)` rather than the head, so a concurrent append can
     * never be the row under test.
     */
    const after = await readState(client);
    const priorHead = before.headHash;
    const stillThere = priorHead !== null && (await headStillPresent(client, priorHead));

    if (after.count >= before.count && stillThere) {
      const grew = after.count - before.count;
      pass(
        `nothing was destroyed: ${String(before.count)} event(s) before, ${String(after.count)} after` +
          (grew > 0n
            ? ` (${String(grew)} appended concurrently, which is not a failure)`
            : ", unchanged") +
          `, and the pre-probe head still hashes the same`,
      );
    } else if (after.count < before.count) {
      fail(
        `the chain SHRANK during the probe, ${String(before.count)} -> ${String(after.count)} events: ` +
          `a delete or truncate took effect`,
      );
    } else {
      fail(
        `the event that was the head at the start is gone or altered ` +
          `(hash ${priorHead?.slice(0, 16) ?? "none"}...), so a modification took effect`,
      );
    }

    /**
     * Layer 3, and this check is DELIBERATELY WORDED DOWN because testing it exposed how little it
     * proves. Recorded in full so nobody strengthens the claim back again.
     *
     * The obvious reading of a passing `has_table_privilege('public', ...)` is "the REVOKE ran". It is
     * not. Postgres grants PUBLIC no privileges on a newly created table in the first place, so this
     * returns false whether `REVOKE UPDATE, DELETE, TRUNCATE` was applied or the table was simply
     * created and left alone. Verified rather than reasoned: against a scratch database built from the
     * table DDL with `sql/audit-immutability.sql` never applied, this assertion passed while all three
     * trigger assertions correctly failed.
     *
     * So what it actually detects is someone having explicitly GRANTed one of the three to PUBLIC, which
     * is a real misconfiguration and a narrow one. It cannot confirm the REVOKE, and in the default
     * single-role setup it says nothing about the service's own access either, because the service
     * connects as the table OWNER and an owner's privileges do not come from PUBLIC.
     *
     * Kept anyway, at its true weight, because a wrong GRANT should be caught. The trigger is the
     * load-bearing layer in this posture, which is the whole reason the restricted-role deployment
     * matters: under that setup the REVOKE becomes a real boundary and this check becomes meaningful.
     */
    const priv = await client.query<{ upd: boolean; del: boolean; trunc: boolean }>(
      `SELECT has_table_privilege('public', 'audit_events', 'UPDATE')   AS upd,
              has_table_privilege('public', 'audit_events', 'DELETE')   AS del,
              has_table_privilege('public', 'audit_events', 'TRUNCATE') AS trunc`,
    );
    const p = priv.rows[0];
    if (p && !p.upd && !p.del && !p.trunc) {
      pass(
        "no UPDATE, DELETE or TRUNCATE is granted to PUBLIC on audit_events " +
          "(weak: Postgres grants none by default, so this catches a stray GRANT, it does not confirm the REVOKE)",
      );
    } else {
      fail(
        `PUBLIC has been GRANTed privileges on audit_events, which the REVOKE is meant to remove: ` +
          `update=${String(p?.upd)} delete=${String(p?.del)} truncate=${String(p?.trunc)}`,
      );
    }

    /**
     * The intended surface still works.
     *
     * Without this, a table that refused EVERYTHING, including appends, would pass every check above. An
     * append-only log that cannot be appended to is broken in a way that matters more than any of the
     * refusals, and it would present as a clean run.
     *
     * Through `appendAuditEvent` rather than a raw INSERT, so the row it leaves is a properly chained
     * event and `pnpm audit:verify` still passes afterwards. It cannot be rolled back for the same reason
     * the contention probe's rows cannot be cleaned up: the table refuses DELETE, which is the point.
     */
    const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: targetUrl }) });
    try {
      const appended = await appendAuditEvent(prisma, {
        action: "probe.immutability",
        actorType: "system",
        actorId: "immutability-probe",
        metadata: { note: "appended to prove the table still accepts writes" },
      });
      pass(
        `append still works: wrote seq ${String(appended.seq)}, so the refusals above are selective`,
      );
    } catch (err) {
      const { message } = asPgError(err);
      fail(
        `append FAILED, so this table is broken rather than append-only: ${message.slice(0, 200)}`,
      );
    } finally {
      await prisma.$disconnect().catch(() => undefined);
    }
  } finally {
    await client.end().catch(() => undefined);
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
    // Falls back to the whole error when the message is empty, which a Postgres that simply is not
    // running produces. A tool run by someone already worried about their audit log must not fail with a
    // bare newline.
    const message = err instanceof Error && err.message ? err.message : String(err);
    process.stderr.write(`${message || "failed with an empty error"}\n`);
    if (err instanceof Error && err.stack && !err.message) process.stderr.write(`${err.stack}\n`);
    process.exitCode = 1;
  });
}
