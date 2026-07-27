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
  type Tenant,
  type TenantId,
} from "@compliance-kit/common";
import { PrismaClient as MasterPrismaClient, Prisma as MasterPrisma } from "./generated/master/client";
import { PrismaClient as TenantPrismaClient } from "./generated/tenant/client";

export type MasterDb = MasterPrismaClient;
export type TenantDb = TenantPrismaClient;

/** A tenant row as the master registry stores it. */
type TenantRecord = {
  id: string;
  slug: string;
  databaseName: string;
  status: "provisioning" | "active" | "suspended";
};

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

/** Postgres identifiers: lowercase, letter-initial, and short enough to be a db name. */
const SAFE_DB_NAME = /^[a-z][a-z0-9_]{0,62}$/;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Prisma's unique-constraint violation. */
const UNIQUE_VIOLATION = "P2002";

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

    if (!row || row.status !== "active") throw new TenantNotFoundError(idOrSlug);
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
   */
  async provisionTenant(input: ProvisionTenantInput): Promise<Tenant> {
    const databaseName = `tenant_${input.slug}`.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    if (!SAFE_DB_NAME.test(databaseName)) {
      throw new Error(`Derived database name is not a safe identifier: ${databaseName}`);
    }

    let row: TenantRecord;
    try {
      row = await this.master.tenant.create({
        data: { slug: input.slug, name: input.name, databaseName, status: "provisioning" },
      });
    } catch (err) {
      if (
        err instanceof MasterPrisma.PrismaClientKnownRequestError &&
        err.code === UNIQUE_VIOLATION
      ) {
        throw new TenantAlreadyExistsError(input.slug);
      }
      throw err;
    }

    await this.createDatabase(databaseName);
    await this.initializeTenantDatabase(databaseName);

    const active = await this.master.tenant.update({
      where: { id: row.id },
      data: { status: "active" },
    });
    return this.toTenant(active);
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
   * Apply the generated schema to a freshly-created tenant database and seed its RBAC
   * catalogue, in a single transaction. Postgres makes DDL transactional, so either the
   * tenant database ends up complete and usable or it stays empty and the tenant stays
   * `provisioning`. There is no half-provisioned state to reason about.
   *
   * Seeds the permission catalogue and the tenant-admin role, and grants every permission
   * to that role. Creates no users: see the note on provisionTenant.
   */
  private async initializeTenantDatabase(databaseName: string): Promise<void> {
    const client = new Client({ connectionString: this.tenantConnectionString(databaseName) });
    await client.connect();
    try {
      await client.query("BEGIN");

      await client.query(this.loadTenantDdl());

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

      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      await client.end();
    }
  }
}
