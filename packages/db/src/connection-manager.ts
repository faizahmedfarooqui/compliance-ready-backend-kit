import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { Client, Pool } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";
import {
  DEFAULT_PERMISSIONS,
  TENANT_ADMIN_ROLE_DESCRIPTION,
  TENANT_ADMIN_ROLE_NAME,
  TenantAlreadyExistsError,
  TenantNotFoundError,
  TenantProvisioningInProgressError,
  type Tenant,
  type TenantId,
} from "@compliance-kit/common";
import {
  PrismaClient as MasterPrismaClient,
  Prisma as MasterPrisma,
} from "./generated/master/client";
import { PrismaClient as TenantPrismaClient } from "./generated/tenant/client";

export type MasterDb = MasterPrismaClient;
export type TenantDb = TenantPrismaClient;

/** A tenant row as the master registry stores it. */
interface TenantRecord {
  id: string;
  slug: string;
  databaseName: string;
  status: "provisioning" | "active" | "suspended";
}

export interface ManagerOptions {
  /** Connection string for the master (control-plane) database. */
  masterUrl: string;
  /** Base connection string for the tenant cluster; the per-tenant db name is appended. */
  tenantClusterUrl: string;
  /** Max pooled connections per database. Multiplied by the number of live tenants. */
  maxConnectionsPerDatabase?: number;
  /**
   * Called when a pooled connection fails while idle. Wire this to your logger: these
   * are not request errors, so there is no caller to return them to, and silently
   * dropping them hides real infrastructure faults.
   */
  onPoolError?: (err: Error, databaseName: string) => void;
}

export interface ProvisionTenantInput {
  slug: string;
  name: string;
}

export interface ProvisionedTenant {
  tenant: Tenant;
  /** True when this call finished a provisioning that an earlier call started and did not complete. */
  resumed: boolean;
}

/** Postgres identifiers: lowercase, letter-initial, and short enough to be a db name. */
const SAFE_DB_NAME = /^[a-z][a-z0-9_]{0,62}$/;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Prisma's unique-constraint violation. */
const UNIQUE_VIOLATION = "P2002";

/**
 * SQLSTATEs the tenant schema raises when an object it creates already exists: a type (42710, the
 * schema's first statements create enums) or a table (42P07).
 */
const DUPLICATE_OBJECT = new Set(["42710", "42P07"]);

/**
 * Advisory lock namespace for provisioning: "crbk" in ASCII, as the FIRST key of Postgres's two-integer
 * lock form, with the second derived from the database name.
 *
 * The two-integer form rather than another 64-bit constant, because the two forms never conflict, even
 * where their bits coincide: pg_locks keeps them apart by objsubid (1 for the single 64-bit key, 2 for
 * the pair). So this lock cannot serialise against the audit chain's, which is the single-key form and
 * also begins "crbk". Every provisioning in flight shows up as
 * `SELECT * FROM pg_locks WHERE locktype = 'advisory' AND classid = 1668440683 AND objsubid = 2`.
 */
const PROVISIONING_LOCK_NAMESPACE = 0x6372626b;

/**
 * The database a tenant's data lives in: `tenant_<slug>`, lowercased, with anything outside [a-z0-9_]
 * turned into an underscore, then validated as an identifier, because it reaches DDL.
 */
export function tenantDatabaseName(slug: string): string {
  const databaseName = `tenant_${slug}`.toLowerCase().replace(/[^a-z0-9_]/g, "_");
  if (!SAFE_DB_NAME.test(databaseName)) {
    throw new Error(`Derived database name is not a safe identifier: ${databaseName}`);
  }
  return databaseName;
}

/**
 * The advisory lock a provisioning run holds for one database name. Exported for the provisioning
 * probe, which has to hold the same lock to prove that a second run is refused.
 *
 * The second key is 32 bits of a hash, so two names can share a lock. What that costs is a spurious
 * TenantProvisioningInProgressError for one of them while the other is running, never a wrong result.
 */
export function provisioningLockKeys(databaseName: string): [number, number] {
  return [
    PROVISIONING_LOCK_NAMESPACE,
    createHash("sha256").update(databaseName).digest().readInt32BE(0),
  ];
}

/**
 * What a tenant database's COMMENT holds once it is fully built: the id of the registry row it was
 * built for. See initializeTenantDatabase for why that is what makes a retry safe.
 */
export function tenantDatabaseMarker(tenantId: string): string {
  return `crbk-tenant:${tenantId}`;
}

/**
 * The tenant's database name is taken by a database this provisioning did not build: one marked for a
 * different registry row, or one that already holds tenant tables and carries no marker. The second is
 * what a database left behind by a deleted tenant looks like, and what a tenant built before the marker
 * existed looks like. Adopting either would hand this tenant someone else's users and audit history.
 *
 * Deliberately not a DomainError. The request was valid and the conflict is in the cluster, so it is
 * answered as a 500 whose cause goes to the log, and an operator decides what the database is. The
 * tenant stays `provisioning` meanwhile, and a retry resumes it once the name is free.
 */
export class TenantDatabaseConflictError extends Error {
  constructor(
    readonly databaseName: string,
    reason: string,
  ) {
    super(
      `Refusing to provision into database "${databaseName}": ${reason}. It was not built for this ` +
        `tenant, so it is left exactly as it was. Find out what it is before changing anything; once ` +
        `the name is free, repeating the request resumes the provisioning.`,
    );
    this.name = "TenantDatabaseConflictError";
  }
}

function isDuplicateObject(err: unknown): boolean {
  if (typeof err !== "object" || err === null || !("code" in err)) return false;
  return typeof err.code === "string" && DUPLICATE_OBJECT.has(err.code);
}

/**
 * Owns the master pool and a cache of per-tenant pools. Resolving a tenant and getting
 * its database are the two operations request handling needs; provisioning creates a
 * brand-new physically-isolated database for a tenant.
 *
 * Prisma 7 requires a driver adapter, which is what makes database-per-tenant clean
 * here: we construct the `pg` Pool ourselves, so connection limits, lifetimes, and
 * error handling stay under our control, and routing a request to a different database
 * is just a different pool. See docs/ARCHITECTURE notes in README.
 */
export class ConnectionManager {
  private readonly masterPool: Pool;
  readonly master: MasterDb;
  private readonly tenantCache = new Map<TenantId, { pool: Pool; db: TenantDb }>();
  private tenantDdl: string | undefined;
  private auditImmutabilityDdl: string | undefined;

  constructor(private readonly opts: ManagerOptions) {
    this.masterPool = this.createPool(opts.masterUrl, "master");
    this.master = new MasterPrismaClient({ adapter: new PrismaPg(this.masterPool) });
  }

  /** Look up an active tenant by id or slug. Throws if unknown or not active. */
  async resolveTenant(idOrSlug: string): Promise<Tenant> {
    // Branch on the shape of the input rather than OR-ing both columns. `tenants.id` is
    // uuid, and Postgres evaluates every branch of an OR, so comparing it against a
    // slug like "acme" raises 22P02 (invalid input syntax for type uuid) instead of
    // simply not matching.
    const row = UUID.test(idOrSlug)
      ? await this.master.tenant.findUnique({ where: { id: idOrSlug } })
      : await this.master.tenant.findUnique({ where: { slug: idOrSlug } });

    if (row?.status !== "active") throw new TenantNotFoundError(idOrSlug);
    return this.toTenant(row);
  }

  /** Get (and cache) a Prisma client bound to this tenant's dedicated database. */
  getTenantDb(tenant: Tenant): TenantDb {
    const cached = this.tenantCache.get(tenant.id);
    if (cached) return cached.db;

    const pool = this.createPool(
      this.tenantConnectionString(tenant.databaseName),
      tenant.databaseName,
    );
    const db = new TenantPrismaClient({ adapter: new PrismaPg(pool) });
    this.tenantCache.set(tenant.id, { pool, db });
    return db;
  }

  /**
   * Provision a new tenant: register it, create its dedicated database, then apply the
   * schema and seed its RBAC catalogue.
   *
   * This creates NO users. A tenant's first administrator is created separately, by the
   * seed script (`pnpm db:seed:admin`, see src/seed/seed-tenant-admin.ts). Keeping the
   * two apart means creating infrastructure and granting a human administrative access
   * are distinct, separately auditable actions, and it keeps credentials out of the
   * provisioning request body.
   *
   * `CREATE DATABASE` cannot run inside a transaction, so this is a sequence of
   * autocommit steps with the `status` column as the completion marker: a tenant stays
   * `provisioning` (and so cannot be resolved for a request) until its database is
   * fully built. Everything after the CREATE DATABASE does run in one transaction, so a
   * tenant database is never left with tables but no roles.
   *
   * RESUMABLE. A run can stop after any step: the database create can fail, the schema transaction
   * can roll back, the process can die, or the database can be finished and the final status update
   * lost. Each of those leaves the row in `provisioning`, and the row is what makes the slug taken, so
   * before this was resumable every retry was a 409 and the slug stayed unusable until someone edited
   * the registry by hand. Now repeating the request, same slug and same name, picks the run up where
   * it stopped: each step checks what an earlier run already did and does only what is missing. A
   * different name is still a 409, because that is a different request that wants the same slug.
   *
   * Two things keep a retry from doing harm. Every run holds a per-database advisory lock for its
   * whole length, so a retry cannot start while the original is still working; it gets
   * TenantProvisioningInProgressError instead. And a database that is already built is accepted only
   * if its marker names THIS registry row (see initializeTenantDatabase), so a database with the same
   * name that was built for another row is refused, not adopted.
   */
  async provisionTenant(input: ProvisionTenantInput): Promise<ProvisionedTenant> {
    const databaseName = tenantDatabaseName(input.slug);

    const lock = await this.lockProvisioning(databaseName);
    if (!lock) throw new TenantProvisioningInProgressError(input.slug);
    try {
      const { row, resumed } = await this.registerOrResume(input, databaseName);

      await this.createDatabase(databaseName);
      await this.initializeTenantDatabase(databaseName, row.id);

      const active = await this.master.tenant.update({
        where: { id: row.id },
        data: { status: "active" },
      });
      return { tenant: this.toTenant(active), resumed };
    } finally {
      await lock.release();
    }
  }

  async close(): Promise<void> {
    for (const { pool, db } of this.tenantCache.values()) {
      await db.$disconnect();
      await pool.end();
    }
    this.tenantCache.clear();
    await this.master.$disconnect();
    await this.masterPool.end();
  }

  // --- internals ---

  /**
   * Find the registry row this run continues, or create it.
   *
   * Runs under the provisioning lock, which is what makes reading and then inserting safe against
   * another run of this code. The unique constraints still back it up, for a run that does not take
   * the lock: an instance on an older version of the kit, during a rolling deploy.
   */
  private async registerOrResume(
    input: ProvisionTenantInput,
    databaseName: string,
  ): Promise<{ row: TenantRecord; resumed: boolean }> {
    const existing = await this.master.tenant.findUnique({ where: { slug: input.slug } });
    if (existing) {
      // Only an unfinished run of the SAME request is resumed. An active or suspended tenant is
      // final, and a different name is a different request for the same slug, which must not
      // quietly complete someone else's.
      if (existing.status !== "provisioning" || existing.name !== input.name) {
        throw new TenantAlreadyExistsError(input.slug);
      }
      // The name is derived from the slug, so a row that disagrees was not written by this code.
      if (existing.databaseName !== databaseName) {
        throw new TenantDatabaseConflictError(
          databaseName,
          `the registry row for "${input.slug}" names database "${existing.databaseName}"`,
        );
      }
      return { row: existing, resumed: true };
    }

    try {
      const row = await this.master.tenant.create({
        data: { slug: input.slug, name: input.name, databaseName, status: "provisioning" },
      });
      return { row, resumed: false };
    } catch (err) {
      if (
        err instanceof MasterPrisma.PrismaClientKnownRequestError &&
        err.code === UNIQUE_VIOLATION
      ) {
        throw new TenantAlreadyExistsError(input.slug);
      }
      throw err;
    }
  }

  /**
   * Take the provisioning lock for one database name, or return undefined if another run holds it.
   *
   * Session-level, because no single transaction spans a run: CREATE DATABASE cannot be inside one.
   * And on a DEDICATED connection rather than one from the pool, because a session-level lock belongs
   * to its connection: handed back to the pool, it would stay held by an idle connection and keep that
   * name locked until the pool happened to close it. Ending the connection is what releases the lock,
   * so it is released however the run ends, and if the process dies Postgres drops it with the session.
   */
  private async lockProvisioning(
    databaseName: string,
  ): Promise<{ release: () => Promise<void> } | undefined> {
    const client = new Client({ connectionString: this.opts.masterUrl });
    // The connection sits idle while the run works, so losing it arrives as an 'error' event rather
    // than as a failed query, and an unhandled 'error' on a pg Client is fatal to the process. Losing
    // it also releases the lock early. The run carries on, which is safe: the lock turns a duplicate
    // run into a clear 409, and without it Postgres still refuses a second CREATE DATABASE or a second
    // copy of the schema, so a duplicate fails rather than building anything twice.
    client.on("error", (err) => this.opts.onPoolError?.(err, "master"));
    await client.connect();
    const release = async (): Promise<void> => {
      await client.end().catch(() => undefined);
    };

    const result = await client
      .query<{ locked: boolean }>(
        "SELECT pg_try_advisory_lock($1, $2) AS locked",
        provisioningLockKeys(databaseName),
      )
      .catch(async (err: unknown) => {
        await release();
        throw err;
      });
    if (result.rows[0]?.locked === true) return { release };
    await release();
    return undefined;
  }

  /**
   * A `pg` Pool emits 'error' when a connection fails while sitting IDLE (the server
   * restarted, a proxy dropped it). Node treats an 'error' event with no listener as
   * fatal, so a single dropped idle connection would take the whole process down and
   * with it every other tenant. Attach a listener; pg discards the bad client itself.
   */
  private createPool(connectionString: string, databaseName: string): Pool {
    const pool = new Pool({
      connectionString,
      ...(this.opts.maxConnectionsPerDatabase !== undefined
        ? { max: this.opts.maxConnectionsPerDatabase }
        : {}),
    });
    pool.on("error", (err) => this.opts.onPoolError?.(err, databaseName));
    return pool;
  }

  private toTenant(row: TenantRecord): Tenant {
    return {
      id: row.id,
      slug: row.slug,
      databaseName: row.databaseName,
      status: row.status,
    };
  }

  private tenantConnectionString(databaseName: string): string {
    const url = new URL(this.opts.tenantClusterUrl);
    url.pathname = `/${databaseName}`;
    return url.toString();
  }

  /** The tenant schema as SQL, generated from prisma/tenant/schema.prisma. */
  private loadTenantDdl(): string {
    // Resolves from both src/ (ts-node) and dist/ (compiled), since sql/ sits beside both.
    this.tenantDdl ??= readFileSync(
      path.resolve(__dirname, "..", "sql", "tenant-schema.sql"),
      "utf8",
    );
    return this.tenantDdl;
  }

  /**
   * Append-only enforcement for the tenant's audit log.
   *
   * A SEPARATE file from the generated schema, and it has to be. `prisma migrate diff` renders what the
   * Prisma schema can express, and triggers, functions and REVOKE are not among those things, so the
   * generated DDL creates the audit table with no protection on it whatsoever. Regenerating that file
   * would also discard anything appended to it by hand, which is why this is not appended.
   *
   * The consequence worth stating: a tenant provisioned WITHOUT this step has an audit table that
   * accepts UPDATE and DELETE, so its log is ordinary rows that happen to carry hashes. That is why it
   * runs in the same transaction as the schema, below, rather than as a follow-up step that could fail
   * on its own and leave a tenant half protected.
   */
  private loadAuditImmutabilitySql(): string {
    this.auditImmutabilityDdl ??= readFileSync(
      path.resolve(__dirname, "..", "sql", "audit-immutability.sql"),
      "utf8",
    );
    return this.auditImmutabilityDdl;
  }

  /** Create the tenant database via a maintenance connection, if it does not exist. */
  private async createDatabase(databaseName: string): Promise<void> {
    const maintenanceUrl = new URL(this.opts.tenantClusterUrl);
    maintenanceUrl.pathname = "/postgres";
    const client = new Client({ connectionString: maintenanceUrl.toString() });
    await client.connect();
    try {
      const exists = await client.query("SELECT 1 FROM pg_database WHERE datname = $1", [
        databaseName,
      ]);
      if (exists.rowCount === 0) {
        // Identifier is validated against SAFE_DB_NAME above; still double-quote it.
        await client.query(`CREATE DATABASE "${databaseName}"`);
      }
    } finally {
      await client.end();
    }
  }

  /**
   * Apply the generated schema to a tenant database and seed its RBAC catalogue, in a single
   * transaction. Postgres makes DDL transactional, so either the tenant database ends up complete
   * and usable or it is left as it was and the tenant stays `provisioning`. The database itself
   * can exist without the schema, since CREATE DATABASE commits on its own; the row's status is what
   * keeps that state from being served.
   *
   * Seeds the permission catalogue and the tenant-admin role, and grants every permission
   * to that role. Creates no users: see the note on provisionTenant.
   *
   * THE MARKER. The transaction's last statement sets the database's COMMENT to
   * tenantDatabaseMarker(tenantId), so a database carries the marker exactly when its build
   * committed, and the marker says which registry row it was built for. That is what makes a retry
   * safe, because a database with the right NAME is not necessarily this tenant's:
   *
   *   - Marked for this row: an earlier run built it, then failed before marking the tenant active.
   *     Nothing to do.
   *   - No marker and no tenant tables: a create that never reached a committed build. Build it.
   *   - Marked for another row, or holding tenant tables with no marker: built for someone else,
   *     such as a tenant whose registry row was deleted and its database kept, or a tenant from
   *     before the marker existed. Refused, and left exactly as found. Adopting it would give this
   *     tenant another tenant's users and audit log, the one outcome database-per-tenant exists to
   *     rule out.
   *
   * "No tenant tables" is judged by the schema failing on a duplicate object rather than by
   * checking that the database is empty, because it need not be: CREATE DATABASE copies template1,
   * and a cluster that installs an extension there gives every new database that extension's objects.
   */
  private async initializeTenantDatabase(databaseName: string, tenantId: string): Promise<void> {
    // Both are interpolated into the COMMENT statement below, which cannot take bind parameters.
    if (!SAFE_DB_NAME.test(databaseName) || !UUID.test(tenantId)) {
      throw new Error(
        `Refusing to mark "${databaseName}" for "${tenantId}": not a safe identifier`,
      );
    }
    const marker = tenantDatabaseMarker(tenantId);

    const client = new Client({ connectionString: this.tenantConnectionString(databaseName) });
    await client.connect();
    try {
      await client.query("BEGIN");

      const found = await client.query<{ marker: string | null }>(
        "SELECT shobj_description(oid, 'pg_database') AS marker FROM pg_database " +
          "WHERE datname = current_database()",
      );
      const current = found.rows[0]?.marker ?? null;
      if (current === marker) {
        await client.query("ROLLBACK");
        return;
      }
      if (current !== null) {
        throw new TenantDatabaseConflictError(
          databaseName,
          `it is marked "${current}", not "${marker}"`,
        );
      }

      try {
        await client.query(this.loadTenantDdl());
      } catch (err) {
        if (isDuplicateObject(err)) {
          throw new TenantDatabaseConflictError(
            databaseName,
            "it already holds tenant tables and carries no provisioning marker",
          );
        }
        throw err;
      }
      // Immediately after the schema and inside the same transaction: an audit table without its
      // triggers is not append-only, and a tenant must never exist in that state.
      await client.query(this.loadAuditImmutabilitySql());

      // Permission catalogue. Values come from DEFAULT_PERMISSIONS so the seeded rows
      // and the keys checked by @TenantAuthenticated have a single source of truth.
      const permissionTuples = DEFAULT_PERMISSIONS.map(
        (_, i) => `($${i * 2 + 1}, $${i * 2 + 2})`,
      ).join(", ");
      await client.query(
        `INSERT INTO permissions (key, description) VALUES ${permissionTuples}`,
        DEFAULT_PERMISSIONS.flatMap((p) => [p.key, p.description]),
      );

      const role = await client.query<{ id: string }>(
        `INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id`,
        [TENANT_ADMIN_ROLE_NAME, TENANT_ADMIN_ROLE_DESCRIPTION],
      );

      await client.query(
        `INSERT INTO role_permissions (role_id, permission_id) SELECT $1, id FROM permissions`,
        [role.rows[0].id],
      );

      // LAST, so the marker commits with everything above or not at all. Both values were checked
      // against strict patterns at the top: an identifier and a uuid, neither able to hold a quote.
      await client.query(`COMMENT ON DATABASE "${databaseName}" IS '${marker}'`);

      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      await client.end();
    }
  }
}
