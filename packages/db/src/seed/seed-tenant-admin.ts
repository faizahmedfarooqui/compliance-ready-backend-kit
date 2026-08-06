/**
 * Seed a tenant's first administrator.
 *
 * Provisioning a tenant creates its database and its RBAC catalogue but no users, so a
 * freshly provisioned tenant has nobody who can log in. This script grants one named
 * human the seeded `tenant-admin` role, and it is deliberately a separate, explicit step:
 *
 *  - Creating infrastructure and granting a person administrative access are different
 *    decisions, taken by different people at different times, and an assessor will want to
 *    see them as separate events (HIPAA 164.308(a)(4), PCI Req 7, SOC 2 CC6.3).
 *  - It keeps credentials out of the provisioning HTTP request body.
 *  - It does not depend on promoting "whoever registers first", which would be a race
 *    anyone who learned a tenant slug could win, since POST /auth/register is
 *    unauthenticated.
 *
 * Usage (password via env is preferred; a CLI flag lands in your shell history):
 *
 *   SEED_ADMIN_PASSWORD='...' pnpm db:seed:admin --tenant acme --email admin@acme.example
 *   pnpm db:seed:admin --tenant acme --email admin@acme.example --password '...'
 *
 * Idempotent: re-running for an existing user grants the role without touching the
 * password, so it is safe to use to repair a tenant that lost its administrator.
 */
import { hashPassword } from "@compliance-kit/crypto";
import { TENANT_ADMIN_ROLE_NAME } from "@compliance-kit/common";
import { ConnectionManager } from "../connection-manager";
import { loadLocalDotenv } from "../cli/load-dotenv";

export interface SeedTenantAdminInput {
  /** Tenant id or slug, as accepted by ConnectionManager.resolveTenant. */
  tenant: string;
  email: string;
  password: string;
}

export interface SeedTenantAdminResult {
  tenantSlug: string;
  databaseName: string;
  userId: string;
  email: string;
  role: string;
  created: boolean;
}

/**
 * Create (or find) the user and grant them the tenant-admin role, in one transaction.
 * Exported separately from the CLI so it can be called from tests or an ops tool.
 */
export async function seedTenantAdmin(
  cm: ConnectionManager,
  input: SeedTenantAdminInput,
): Promise<SeedTenantAdminResult> {
  const tenant = await cm.resolveTenant(input.tenant);
  const db = cm.getTenantDb(tenant);
  const email = input.email.trim().toLowerCase();

  const role = await db.role.findUnique({ where: { name: TENANT_ADMIN_ROLE_NAME } });
  if (!role) {
    throw new Error(
      `Tenant "${tenant.slug}" has no "${TENANT_ADMIN_ROLE_NAME}" role. Its database was ` +
        `not provisioned by this version of the kit, or provisioning did not complete.`,
    );
  }

  const existing = await db.user.findUnique({ where: { email }, select: { id: true } });

  // One transaction so a tenant is never left with a new user who holds no role.
  const result = await db.$transaction(async (tx) => {
    const user =
      existing ??
      (await tx.user.create({
        data: { email, passwordHash: await hashPassword(input.password) },
        select: { id: true },
      }));

    await tx.userRole.upsert({
      where: { userId_roleId: { userId: user.id, roleId: role.id } },
      create: { userId: user.id, roleId: role.id },
      update: {},
    });

    return user;
  });

  return {
    tenantSlug: tenant.slug,
    databaseName: tenant.databaseName,
    userId: result.id,
    email,
    role: TENANT_ADMIN_ROLE_NAME,
    created: !existing,
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const [flag, inline] = arg.slice(2).split("=", 2);
    out[flag] = inline ?? argv[++i] ?? "";
  }
  return out;
}

/** Local development convenience only; skipped under NODE_ENV=production. */

const USAGE = `
Seed a tenant's first administrator.

  SEED_ADMIN_PASSWORD='...' pnpm db:seed:admin --tenant <slug|id> --email <address>

Options
  --tenant    tenant slug or uuid (required)
  --email     administrator email address (required)
  --password  password; prefer SEED_ADMIN_PASSWORD so it stays out of shell history

Environment
  MASTER_DATABASE_URL, TENANT_CLUSTER_URL   read from .env for local development
`;

async function main(): Promise<void> {
  loadLocalDotenv();
  const args = parseArgs(process.argv.slice(2));

  const tenant = args.tenant;
  const email = args.email;
  const password = process.env.SEED_ADMIN_PASSWORD ?? args.password;

  const missing = [
    !tenant && "--tenant",
    !email && "--email",
    !password && "--password or SEED_ADMIN_PASSWORD",
  ].filter(Boolean);
  if (missing.length > 0) {
    process.stderr.write(`Missing required: ${missing.join(", ")}\n${USAGE}`);
    process.exitCode = 1;
    return;
  }

  // Deliberately enforced here as well as in the register DTO: a seeded administrator is
  // the most privileged account in a tenant and should not be the weakest password in it.
  if (password.length < 12) {
    process.stderr.write("Password must be at least 12 characters.\n");
    process.exitCode = 1;
    return;
  }

  const masterUrl = process.env.MASTER_DATABASE_URL;
  const tenantClusterUrl = process.env.TENANT_CLUSTER_URL;
  if (!masterUrl || !tenantClusterUrl) {
    process.stderr.write(
      "MASTER_DATABASE_URL and TENANT_CLUSTER_URL must be set. " +
        "Copy .env.example to .env for local development.\n",
    );
    process.exitCode = 1;
    return;
  }

  const cm = new ConnectionManager({
    masterUrl,
    tenantClusterUrl,
    onPoolError: (err, databaseName) =>
      process.stderr.write(`pool error on ${databaseName}: ${err.message}\n`),
  });

  try {
    const result = await seedTenantAdmin(cm, { tenant, email, password });
    process.stdout.write(
      `${result.created ? "Created" : "Found existing"} user ${result.email} ` +
        `(${result.userId}) in ${result.databaseName} and granted "${result.role}".\n`,
    );
  } finally {
    await cm.close();
  }
}

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
