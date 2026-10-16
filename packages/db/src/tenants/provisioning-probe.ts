/**
 * Prove that provisioning resumes what an interrupted run left behind, and refuses what it did not
 * build.
 *
 * WHY A PROBE AND NOT A UNIT TEST. What makes resuming safe lives in Postgres, not in the TypeScript:
 * that CREATE DATABASE commits on its own, that the schema and COMMENT ON DATABASE commit or roll back
 * together, that a session-level advisory lock is held against other sessions and dies with its own,
 * and that the tenant schema fails on a duplicate object. A fake client would assert my beliefs about
 * each of those and pass while any of them was wrong.
 *
 * HOW AN INTERRUPTED RUN IS STAGED. Each scenario writes, directly, the state that a run which stopped
 * at one step would have left, then calls provisionTenant exactly as the service does:
 *
 *   - stopped after registering:       a `provisioning` row and no database
 *   - stopped after CREATE DATABASE:   a `provisioning` row and an empty database
 *   - lost the final status update:    a `provisioning` row and a database built and marked for it
 *
 * And the two databases a retry must NOT adopt, because each belongs to someone else:
 *
 *   - one marked as built for a different registry row
 *   - one holding the tenant schema with no marker, which is what a deleted tenant's leftover database
 *     looks like, and what a tenant built before the marker existed looks like
 *
 * WHAT COUNTS AS A PASS for a refusal is not merely that it threw. The row must still be
 * `provisioning` and the foreign database exactly as it was, down to a sentinel row written into it
 * beforehand, because a refusal that had already changed the database would have done the damage it
 * exists to prevent.
 *
 * Every tenant it makes is named `resume-*`, and it drops each one at the end, database and registry
 * row, failure or not. `pnpm clean:test-tenants` knows the prefix, for a run that is killed. It
 * creates and drops databases on whatever cluster the environment names, so point it at a development
 * or CI cluster, never at a real one.
 *
 * Lives in packages/db rather than scripts/ because `pg` resolves from this package, and because the
 * other operator CLIs live here too.
 *
 * Usage: node packages/db/dist/tenants/provisioning-probe.js
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { Client } from "pg";
import {
  DEFAULT_PERMISSIONS,
  TENANT_ADMIN_ROLE_NAME,
  TenantAlreadyExistsError,
  TenantProvisioningInProgressError,
} from "@compliance-kit/common";
import {
  ConnectionManager,
  TenantDatabaseConflictError,
  provisioningLockKeys,
  tenantDatabaseMarker,
  tenantDatabaseName,
} from "../connection-manager";
import { loadLocalDotenv } from "../cli/load-dotenv";

/** One suffix per run, so a rerun never collides with what an interrupted run left behind. */
const RUN = Date.now().toString(36);

interface RbacCounts {
  adminRoles: number;
  permissions: number;
  grants: number;
}

async function main(): Promise<void> {
  loadLocalDotenv();
  const masterUrl = process.env.MASTER_DATABASE_URL;
  if (!masterUrl) {
    process.stderr.write("MASTER_DATABASE_URL must be set\n");
    process.exitCode = 1;
    return;
  }
  // As in verify-chain.ts: one cluster serving both is the local and CI layout.
  const tenantClusterUrl = process.env.TENANT_CLUSTER_URL ?? masterUrl;

  let failures = 0;
  const fail = (m: string): void => {
    process.stderr.write(`  FAIL  ${m}\n`);
    failures += 1;
  };
  const pass = (m: string): void => {
    process.stdout.write(`  PASS  ${m}\n`);
  };
  const check = (ok: boolean, label: string, why: () => string): void => {
    if (ok) pass(label);
    else fail(`${label}: ${why()}`);
  };

  const urlFor = (databaseName: string): string => {
    const url = new URL(tenantClusterUrl);
    url.pathname = `/${databaseName}`;
    return url.toString();
  };

  const cm = new ConnectionManager({ masterUrl, tenantClusterUrl });
  const master = new Client({ connectionString: masterUrl });
  const cluster = new Client({ connectionString: urlFor("postgres") });
  const made = new Set<string>();

  const slugFor = (scenario: string): string => {
    const slug = `resume-${scenario}-${RUN}`;
    made.add(slug);
    return slug;
  };

  /** A registry row in the state provisionTenant writes before it touches the cluster. */
  const stageRow = async (slug: string, name: string): Promise<string> => {
    const row = await master.query<{ id: string }>(
      "INSERT INTO tenants (slug, name, database_name, status) " +
        "VALUES ($1, $2, $3, 'provisioning') RETURNING id",
      [slug, name, tenantDatabaseName(slug)],
    );
    return row.rows[0].id;
  };

  const rowOf = async (slug: string): Promise<{ status: string; name: string } | undefined> => {
    const row = await master.query<{ status: string; name: string }>(
      "SELECT status::text AS status, name FROM tenants WHERE slug = $1",
      [slug],
    );
    return row.rows[0];
  };

  // Every name below comes from tenantDatabaseName, which validates it as a strict identifier.
  const createDatabase = async (databaseName: string): Promise<void> => {
    await cluster.query(`CREATE DATABASE "${databaseName}"`);
  };

  const databaseExists = async (databaseName: string): Promise<boolean> => {
    const row = await cluster.query("SELECT 1 FROM pg_database WHERE datname = $1", [databaseName]);
    return row.rowCount === 1;
  };

  const markerOf = async (databaseName: string): Promise<string | null> => {
    const row = await cluster.query<{ marker: string | null }>(
      "SELECT shobj_description(oid, 'pg_database') AS marker FROM pg_database WHERE datname = $1",
      [databaseName],
    );
    return row.rows[0]?.marker ?? null;
  };

  const inDatabase = async <T>(databaseName: string, fn: (c: Client) => Promise<T>): Promise<T> => {
    const client = new Client({ connectionString: urlFor(databaseName) });
    await client.connect();
    try {
      return await fn(client);
    } finally {
      await client.end();
    }
  };

  const rbacOf = (databaseName: string): Promise<RbacCounts> =>
    inDatabase(databaseName, async (c) => {
      const row = await c.query<{ admin_roles: number; permissions: number; grants: number }>(
        "SELECT (SELECT count(*)::int FROM roles WHERE name = $1) AS admin_roles, " +
          "(SELECT count(*)::int FROM permissions) AS permissions, " +
          "(SELECT count(*)::int FROM role_permissions) AS grants",
        [TENANT_ADMIN_ROLE_NAME],
      );
      const r = row.rows[0];
      return { adminRoles: r.admin_roles, permissions: r.permissions, grants: r.grants };
    });

  /** Built exactly once: one admin role holding every permission, not two of each. */
  const builtOnce = (rbac: RbacCounts): boolean =>
    rbac.adminRoles === 1 &&
    rbac.permissions === DEFAULT_PERMISSIONS.length &&
    rbac.grants === DEFAULT_PERMISSIONS.length;

  /** The error a call rejected with, or undefined if it resolved. */
  const rejectionOf = async (attempt: Promise<unknown>): Promise<unknown> => {
    try {
      await attempt;
      return undefined;
    } catch (err) {
      return err;
    }
  };

  const describe = (value: unknown): string =>
    value instanceof Error ? `${value.name}: ${value.message}` : JSON.stringify(value);

  try {
    await master.connect();
    await cluster.connect();
    process.stdout.write(`Provisioning probe, run ${RUN}\n`);

    // --- A first provisioning, the baseline every resume is compared with ---------------------
    const fresh = slugFor("fresh");
    const first = await cm.provisionTenant({ slug: fresh, name: "Probe fresh" });
    check(
      first.tenant.status === "active" && !first.resumed,
      "a first provisioning completes and is not reported as resumed",
      () => describe(first),
    );
    const firstMarker = await markerOf(tenantDatabaseName(fresh));
    check(
      firstMarker === tenantDatabaseMarker(first.tenant.id),
      "a first provisioning marks its database with the registry row it was built for",
      () => `marker is ${JSON.stringify(firstMarker)}`,
    );

    // --- Stopped after registering: a row and no database --------------------------------------
    {
      const slug = slugFor("nodb");
      const id = await stageRow(slug, "Probe nodb");
      const result = await cm.provisionTenant({ slug, name: "Probe nodb" });
      const rbac = await rbacOf(tenantDatabaseName(slug));
      check(
        result.resumed &&
          result.tenant.id === id &&
          result.tenant.status === "active" &&
          (await markerOf(tenantDatabaseName(slug))) === tenantDatabaseMarker(id) &&
          builtOnce(rbac),
        "a retry finishes a provisioning that stopped before creating its database",
        () => `${describe(result)} ${JSON.stringify(rbac)}`,
      );
    }

    // --- Stopped after CREATE DATABASE: a row and an empty database ----------------------------
    {
      const slug = slugFor("emptydb");
      const id = await stageRow(slug, "Probe emptydb");
      await createDatabase(tenantDatabaseName(slug));
      const result = await cm.provisionTenant({ slug, name: "Probe emptydb" });
      const rbac = await rbacOf(tenantDatabaseName(slug));
      check(
        result.resumed &&
          result.tenant.id === id &&
          result.tenant.status === "active" &&
          (await markerOf(tenantDatabaseName(slug))) === tenantDatabaseMarker(id) &&
          builtOnce(rbac),
        "a retry finishes a provisioning whose schema never committed, in the database the first run created",
        () => `${describe(result)} ${JSON.stringify(rbac)}`,
      );
    }

    // --- Lost the final status update: a database built and marked, a row still provisioning -----
    {
      const slug = slugFor("built");
      const databaseName = tenantDatabaseName(slug);
      const built = await cm.provisionTenant({ slug, name: "Probe built" });
      await master.query("UPDATE tenants SET status = 'provisioning' WHERE id = $1", [
        built.tenant.id,
      ]);
      // Written after the build, so a retry that rebuilt the database, or reset it, would lose it.
      await inDatabase(databaseName, (c) =>
        c.query("INSERT INTO roles (name, description) VALUES ('probe-sentinel', 'kept')"),
      );
      const result = await cm.provisionTenant({ slug, name: "Probe built" });
      const rbac = await rbacOf(databaseName);
      const sentinel = await inDatabase(databaseName, (c) =>
        c.query("SELECT 1 FROM roles WHERE name = 'probe-sentinel'"),
      );
      check(
        result.resumed &&
          result.tenant.id === built.tenant.id &&
          result.tenant.status === "active" &&
          builtOnce(rbac) &&
          sentinel.rowCount === 1,
        "a retry finishes a provisioning whose database was built but never marked active, without rebuilding it",
        () => `${describe(result)} ${JSON.stringify(rbac)} sentinel rows ${sentinel.rowCount}`,
      );
    }

    // --- A database marked as built for a different registry row ------------------------------
    {
      const slug = slugFor("marked");
      const databaseName = tenantDatabaseName(slug);
      await stageRow(slug, "Probe marked");
      await createDatabase(databaseName);
      const foreignMarker = tenantDatabaseMarker(randomUUID());
      await cluster.query(`COMMENT ON DATABASE "${databaseName}" IS '${foreignMarker}'`);
      await inDatabase(databaseName, async (c) => {
        await c.query("CREATE TABLE probe_foreign (v text)");
        await c.query("INSERT INTO probe_foreign VALUES ('another tenant''s data')");
      });

      const err = await rejectionOf(cm.provisionTenant({ slug, name: "Probe marked" }));
      const row = await rowOf(slug);
      const markerAfter = await markerOf(databaseName);
      const untouched = await inDatabase(databaseName, (c) =>
        c.query<{ rows: number; users: string | null }>(
          "SELECT (SELECT count(*)::int FROM probe_foreign) AS rows, " +
            "to_regclass('public.users')::text AS users",
        ),
      );
      check(
        err instanceof TenantDatabaseConflictError &&
          row?.status === "provisioning" &&
          markerAfter === foreignMarker &&
          untouched.rows[0].rows === 1 &&
          untouched.rows[0].users === null,
        "a retry refuses a database marked as built for a different tenant, and leaves it untouched",
        () =>
          `error ${describe(err)}, row ${JSON.stringify(row)}, marker ${JSON.stringify(markerAfter)}, ` +
          `database ${JSON.stringify(untouched.rows[0])}`,
      );
    }

    // --- A database holding the tenant schema and no marker -------------------------------------
    {
      const slug = slugFor("leftover");
      const databaseName = tenantDatabaseName(slug);
      await stageRow(slug, "Probe leftover");
      await createDatabase(databaseName);
      // The schema exactly as provisioning applies it, without the marker: what a database left by a
      // deleted tenant, or built before the marker existed, contains. Plus a row of that tenant's data.
      const ddl = readFileSync(
        path.resolve(__dirname, "..", "..", "sql", "tenant-schema.sql"),
        "utf8",
      );
      await inDatabase(databaseName, async (c) => {
        await c.query(ddl);
        await c.query(
          "INSERT INTO roles (name, description) VALUES ('leftover-role', 'the previous tenant''s')",
        );
      });

      const err = await rejectionOf(cm.provisionTenant({ slug, name: "Probe leftover" }));
      const row = await rowOf(slug);
      const markerAfter = await markerOf(databaseName);
      const untouched = await inDatabase(databaseName, (c) =>
        c.query<{ leftover: number; admin: number }>(
          "SELECT (SELECT count(*)::int FROM roles WHERE name = 'leftover-role') AS leftover, " +
            "(SELECT count(*)::int FROM roles WHERE name = $1) AS admin",
          [TENANT_ADMIN_ROLE_NAME],
        ),
      );
      check(
        err instanceof TenantDatabaseConflictError &&
          row?.status === "provisioning" &&
          markerAfter === null &&
          untouched.rows[0].leftover === 1 &&
          untouched.rows[0].admin === 0,
        "a retry refuses an unmarked database that already holds the tenant schema, and leaves it untouched",
        () =>
          `error ${describe(err)}, row ${JSON.stringify(row)}, marker ${JSON.stringify(markerAfter)}, ` +
          `database ${JSON.stringify(untouched.rows[0])}`,
      );
    }

    // --- The same slug under a different name ----------------------------------------------------
    {
      const slug = slugFor("rename");
      await stageRow(slug, "Probe original name");
      const err = await rejectionOf(cm.provisionTenant({ slug, name: "Probe other name" }));
      const row = await rowOf(slug);
      const exists = await databaseExists(tenantDatabaseName(slug));
      check(
        err instanceof TenantAlreadyExistsError &&
          row?.status === "provisioning" &&
          row.name === "Probe original name" &&
          !exists,
        "a retry under a different name is refused, and does not touch the unfinished provisioning",
        () => `error ${describe(err)}, row ${JSON.stringify(row)}, database exists ${exists}`,
      );
    }

    // --- Another run holding the lock --------------------------------------------------------------
    {
      const slug = slugFor("locked");
      const databaseName = tenantDatabaseName(slug);
      await stageRow(slug, "Probe locked");
      const holder = new Client({ connectionString: masterUrl });
      await holder.connect();
      let released = false;
      try {
        await holder.query("SELECT pg_advisory_lock($1, $2)", provisioningLockKeys(databaseName));
        const err = await rejectionOf(cm.provisionTenant({ slug, name: "Probe locked" }));
        const exists = await databaseExists(databaseName);
        check(
          err instanceof TenantProvisioningInProgressError &&
            (await rowOf(slug))?.status === "provisioning" &&
            !exists,
          "a retry while another run holds the provisioning lock is refused as in progress, and changes nothing",
          () => `error ${describe(err)}, database exists ${exists}`,
        );
        // Ending the session is the release path provisionTenant relies on, so it is the one used here.
        await holder.end();
        released = true;
        const result = await cm.provisionTenant({ slug, name: "Probe locked" });
        check(
          result.resumed && result.tenant.status === "active",
          "the same retry succeeds once the session holding the lock has ended",
          () => describe(result),
        );
      } finally {
        if (!released) await holder.end().catch(() => undefined);
      }
    }

    // --- Two runs of one new slug at once ----------------------------------------------------------
    {
      const slug = slugFor("race");
      const input = { slug, name: "Probe race" };
      const outcomes = await Promise.allSettled([
        cm.provisionTenant(input),
        cm.provisionTenant(input),
      ]);
      const won = outcomes.filter((o) => o.status === "fulfilled");
      const lost = outcomes.filter((o) => o.status === "rejected");
      const lostCleanly = lost.every(
        (o) =>
          o.reason instanceof TenantProvisioningInProgressError ||
          o.reason instanceof TenantAlreadyExistsError,
      );
      const rbac = await rbacOf(tenantDatabaseName(slug));
      check(
        won.length === 1 && lostCleanly && builtOnce(rbac),
        "two concurrent provisionings of one slug build it once, and the other is refused cleanly",
        () =>
          `${won.length} succeeded, rejections ${lost.map((o) => describe(o.reason)).join("; ")}, ` +
          JSON.stringify(rbac),
      );
    }

    // --- A finished tenant is final ------------------------------------------------------------------
    {
      const err = await rejectionOf(cm.provisionTenant({ slug: fresh, name: "Probe fresh" }));
      check(
        err instanceof TenantAlreadyExistsError,
        "an active tenant's slug is still refused as already existing, even with the same name",
        () => `error ${describe(err)}`,
      );
    }
  } catch (err) {
    fail(`the probe stopped: ${describe(err)}`);
  } finally {
    // Everything this run made, and nothing else: names are tracked as they are handed out.
    let dropped = 0;
    for (const slug of made) {
      const databaseName = tenantDatabaseName(slug);
      try {
        await cluster.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
        await master.query("DELETE FROM tenants WHERE slug = $1", [slug]);
        dropped += 1;
      } catch (err) {
        fail(`could not remove ${slug}, run pnpm clean:test-tenants: ${describe(err)}`);
      }
    }
    process.stdout.write(`Removed ${dropped} of ${made.size} probe tenant(s)\n`);
    await cm.close().catch(() => undefined);
    await master.end().catch(() => undefined);
    await cluster.end().catch(() => undefined);
  }

  if (failures > 0) {
    process.stderr.write(`\n${failures} check(s) failed\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write("\nEvery provisioning check passed\n");
  }
}

void main();
