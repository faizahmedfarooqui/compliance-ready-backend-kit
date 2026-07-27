import path from "node:path";
import { config as loadDotenv } from "dotenv";
import { defineConfig } from "prisma/config";

// The Prisma CLI needs MASTER_DATABASE_URL to run migrations. Load the developer's
// .env explicitly: the CLI runs with cwd = packages/db but the .env lives at the repo
// root, so neither location alone is reliable. dotenv does not overwrite variables
// that are already set, so a real environment always wins over the file.
//
// LOCAL DEVELOPMENT ONLY. In production, migrations run from a deploy job whose
// database URL is injected from KMS / Secrets Manager, never from a committed file.
for (const candidate of [".env", "../../.env"]) {
  loadDotenv({ path: path.resolve(process.cwd(), candidate) });
}

/**
 * `prisma generate` runs on postinstall, before a fresh clone has a .env, and it never
 * opens a connection. So resolve the URL leniently rather than with prisma/config's
 * strict `env()`, which would fail the install outright. The placeholder is named after
 * the variable to set, so a command that DOES connect (migrate) fails with a message
 * that says what is missing instead of "connection refused".
 */
const masterDatabaseUrl =
  process.env.MASTER_DATABASE_URL ?? "postgres://set-MASTER_DATABASE_URL@localhost:5432/master";

export default defineConfig({
  schema: path.join("prisma", "master", "schema.prisma"),
  migrations: { path: path.join("prisma", "master", "migrations") },
  datasource: { url: masterDatabaseUrl },
});
