import path from "node:path";
import { config as loadDotenv } from "dotenv";
import { defineConfig } from "prisma/config";

// See prisma.master.config.ts for why dotenv is loaded here. Local development only.
for (const candidate of [".env", "../../.env"]) {
  loadDotenv({ path: path.resolve(process.cwd(), candidate) });
}

/**
 * The tenant schema is never migrated against one fixed database: every tenant has its
 * own. This config exists only so the Prisma CLI can (a) generate the tenant client and
 * (b) render the tenant schema as SQL via the `tenant:ddl` script.
 *
 * The datasource url below is NOT a tenant database and is never queried by
 * `migrate diff --from-empty`, which is a pure schema-to-SQL rendering. It is required
 * because the Prisma 7 schema engine takes `--datasource` as a mandatory argument and
 * the CLI only populates it from this config. It points at the tenant cluster's
 * maintenance database so that, if a command ever does connect, it connects somewhere
 * real and harmless rather than to one tenant's data.
 */
function tenantClusterMaintenanceUrl(): string {
  // Falls back to a placeholder rather than throwing, so that `prisma generate` works on
  // a fresh clone and in CI before any .env exists. Neither `generate` nor
  // `migrate diff --from-empty` opens a connection, so an unreachable value is harmless
  // here; a command that genuinely needs the cluster will fail loudly on connect.
  const url = new URL(process.env.TENANT_CLUSTER_URL ?? "postgres://placeholder@localhost:5432");
  if (url.pathname === "" || url.pathname === "/") url.pathname = "/postgres";
  return url.toString();
}

export default defineConfig({
  schema: path.join("prisma", "tenant", "schema.prisma"),
  datasource: { url: tenantClusterMaintenanceUrl() },
});
