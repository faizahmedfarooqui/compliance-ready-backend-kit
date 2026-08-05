/**
 * Create and rotate the deployment's token keys.
 *
 * WHY THIS IS A COMMAND AND NOT A MIGRATION. A migration is committed to git, so any key it
 * generated would be identical in every environment that ran it and public to anyone who read the
 * repository. Prisma also replays migrations against a throwaway shadow database, so the work would
 * happen twice against different databases. Key generation is an operational act with a
 * one-per-deployment result; it does not belong in schema history.
 *
 * Usage:
 *   pnpm keys:init                       create the first signing and encryption keys
 *   pnpm keys:rotate                     rotate both purposes
 *   pnpm keys:rotate --purpose signing   rotate one
 *   pnpm keys:list                       show the current state of the registry
 *   pnpm keys:revoke --kid <kid> --reason "<why>"
 *
 * Reads MASTER_DATABASE_URL and KEY_ENCRYPTION_KEY. In production those arrive from KMS / Secrets
 * Manager; locally, from .env.
 */
import {
  LocalKeyProvider,
  generateEncryptionKey,
  generateSigningKey,
  type KeyProvider,
} from "@compliance-kit/crypto";
import { ConnectionManager } from "../connection-manager";
import { loadLocalDotenv } from "../cli/load-dotenv";

type Purpose = "token_signing" | "token_encryption";

const PURPOSES: readonly Purpose[] = ["token_signing", "token_encryption"];

/**
 * How long a retired key keeps verifying.
 *
 * A token signed a moment before rotation must still verify until it expires, so the overlap is the
 * access-token TTL plus the clock tolerance. Shorter and rotation logs every live user out; longer
 * and a key you meant to retire lingers.
 */
function overlapSeconds(): number {
  const ttl = Number(process.env.JWT_ACCESS_TTL_SECONDS ?? 900);
  const skew = Number(process.env.JWT_CLOCK_TOLERANCE_SECONDS ?? 5);
  return (Number.isFinite(ttl) ? ttl : 900) + (Number.isFinite(skew) ? skew : 5);
}

/** Create a key in `pending`, wrapped, never touching the active one. */
async function createPending(
  master: ConnectionManager["master"],
  provider: KeyProvider,
  purpose: Purpose,
): Promise<string> {
  if (purpose === "token_signing") {
    const key = await generateSigningKey();
    const wrapped = await provider.wrap(new TextEncoder().encode(key.privatePkcs8), {
      purpose,
      kid: key.kid,
    });
    await master.configKey.create({
      data: {
        kid: key.kid,
        purpose,
        algorithm: "ES256",
        state: "pending",
        wrappedKey: Buffer.from(wrapped),
        kekId: provider.id,
        // Spread into a plain object rather than asserting. Prisma's Json input wants a
        // JSON-serialisable value, and a spread produces exactly that without a cast that
        // no-unnecessary-type-assertion would (correctly) argue about.
        publicJwk: { ...key.publicJwk },
      },
    });
    return key.kid;
  }

  const key = generateEncryptionKey();
  const wrapped = await provider.wrap(key.secret, { purpose, kid: key.kid });
  await master.configKey.create({
    data: {
      kid: key.kid,
      purpose,
      algorithm: "A256KW",
      state: "pending",
      wrappedKey: Buffer.from(wrapped),
      kekId: provider.id,
    },
  });
  return key.kid;
}

/**
 * Promote a pending key and retire whatever was active, in ONE transaction.
 *
 * The partial unique index means two active keys for a purpose cannot coexist, so the retire and the
 * activate have to happen together or the second statement fails. Doing it in a transaction also
 * means a crash between them cannot leave the deployment with no active key, which would be a total
 * authentication outage.
 */
async function activate(
  master: ConnectionManager["master"],
  purpose: Purpose,
  kid: string,
): Promise<{ retired: string | undefined }> {
  const notAfter = new Date(Date.now() + overlapSeconds() * 1000);

  return master.$transaction(async (tx) => {
    const current = await tx.configKey.findFirst({ where: { purpose, state: "active" } });

    if (current) {
      await tx.configKey.update({
        where: { kid: current.kid },
        data: { state: "retiring", retiringAt: new Date(), notAfter },
      });
    }
    await tx.configKey.update({
      where: { kid },
      data: { state: "active", activatedAt: new Date() },
    });

    return { retired: current?.kid };
  });
}

async function init(cm: ConnectionManager, provider: KeyProvider): Promise<void> {
  for (const purpose of PURPOSES) {
    const existing = await cm.master.configKey.findFirst({ where: { purpose, state: "active" } });
    if (existing) {
      process.stdout.write(`  ${purpose}: already active (${existing.kid}), leaving alone\n`);
      continue;
    }
    const kid = await createPending(cm.master, provider, purpose);
    await activate(cm.master, purpose, kid);
    process.stdout.write(`  ${purpose}: created and activated ${kid}\n`);
  }
}

async function rotate(cm: ConnectionManager, provider: KeyProvider, only?: Purpose): Promise<void> {
  for (const purpose of only ? [only] : PURPOSES) {
    const kid = await createPending(cm.master, provider, purpose);
    const { retired } = await activate(cm.master, purpose, kid);
    process.stdout.write(
      `  ${purpose}: activated ${kid}` +
        (retired ? `, retiring ${retired} for ${overlapSeconds()}s\n` : " (nothing to retire)\n"),
    );
  }
}

async function list(cm: ConnectionManager): Promise<void> {
  const rows = await cm.master.configKey.findMany({
    orderBy: [{ purpose: "asc" }, { createdAt: "asc" }],
  });
  if (rows.length === 0) {
    process.stdout.write("  (empty: run `pnpm keys:init`)\n");
    return;
  }
  for (const r of rows) {
    const until = r.notAfter ? ` until ${r.notAfter.toISOString()}` : "";
    process.stdout.write(
      `  ${r.purpose.padEnd(17)} ${r.state.padEnd(9)} ${r.algorithm.padEnd(7)} ${r.kid}${until}\n`,
    );
  }
}

/**
 * Revoke immediately, destroying the material and keeping the row.
 *
 * Destroying `wrapped_key` is the point: a revoked key that still holds its ciphertext has not
 * really been revoked, and the database CHECK constraint enforces that pairing. The row survives
 * because "this key existed, and was revoked at this time for this reason" is the evidence an
 * assessor asks for.
 */
async function revoke(cm: ConnectionManager, kid: string, reason: string): Promise<void> {
  const key = await cm.master.configKey.findUnique({ where: { kid } });
  if (!key) throw new Error(`No key with kid ${kid}`);
  if (key.state === "revoked") {
    process.stdout.write(`  ${kid} was already revoked\n`);
    return;
  }
  if (key.state === "active") {
    throw new Error(
      `${kid} is the ACTIVE ${key.purpose} key. Revoking it would stop the service issuing ` +
        `tokens. Run \`pnpm keys:rotate --purpose ${key.purpose.replace("token_", "")}\` first, ` +
        `then revoke this kid.`,
    );
  }
  await cm.master.configKey.update({
    where: { kid },
    data: { state: "revoked", wrappedKey: null, revokedAt: new Date(), revokedReason: reason },
  });
  process.stdout.write(`  revoked ${kid}: ${reason}\n`);
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
Manage the deployment's access-token keys.

  pnpm keys:init                      create and activate the first key of each purpose
  pnpm keys:rotate [--purpose P]      create, activate, and retire the previous key
  pnpm keys:list                      show the registry
  pnpm keys:revoke --kid K --reason R revoke a non-active key, destroying its material

  P is "signing" or "encryption". Omit to rotate both.

Environment: MASTER_DATABASE_URL, KEY_ENCRYPTION_KEY
`;

function resolvePurpose(value: string | undefined): Purpose | undefined {
  if (!value) return undefined;
  if (value === "signing" || value === "token_signing") return "token_signing";
  if (value === "encryption" || value === "token_encryption") return "token_encryption";
  throw new Error(`Unknown purpose "${value}". Use "signing" or "encryption".`);
}

async function main(): Promise<void> {
  loadLocalDotenv();
  const args = parseArgs(process.argv.slice(2));
  const command = process.argv.slice(2).find((a) => !a.startsWith("--")) ?? "list";

  const masterUrl = process.env.MASTER_DATABASE_URL;
  const kek = process.env.KEY_ENCRYPTION_KEY;
  if (!masterUrl || !kek) {
    process.stderr.write(
      "MASTER_DATABASE_URL and KEY_ENCRYPTION_KEY must be set. " +
        "Copy .env.example to .env for local development.\n",
    );
    process.exitCode = 1;
    return;
  }

  const kekBytes = new Uint8Array(Buffer.from(kek, "base64url"));
  if (kekBytes.byteLength !== 32) {
    process.stderr.write("KEY_ENCRYPTION_KEY must be a base64url-encoded 256-bit key.\n");
    process.exitCode = 1;
    return;
  }

  const cm = new ConnectionManager({
    masterUrl,
    // Unused by these commands, but ConnectionManager requires it. Pointing it at the master URL
    // keeps the construction honest rather than passing a fake.
    tenantClusterUrl: masterUrl,
    onPoolError: (err, db) => process.stderr.write(`pool error on ${db}: ${err.message}\n`),
  });
  const provider = new LocalKeyProvider(kekBytes);

  try {
    switch (command) {
      case "init":
        process.stdout.write("Initialising token keys:\n");
        await init(cm, provider);
        break;
      case "rotate":
        process.stdout.write("Rotating token keys:\n");
        await rotate(cm, provider, resolvePurpose(args.purpose));
        break;
      case "list":
        process.stdout.write("config_keys:\n");
        await list(cm);
        break;
      case "revoke": {
        if (!args.kid || !args.reason) {
          process.stderr.write(`revoke needs --kid and --reason\n${USAGE}`);
          process.exitCode = 1;
          return;
        }
        await revoke(cm, args.kid, args.reason);
        break;
      }
      default:
        process.stderr.write(`Unknown command "${command}"\n${USAGE}`);
        process.exitCode = 1;
    }
  } finally {
    await cm.close();
  }
}

export { activate, createPending, init, revoke, rotate };
export type { Purpose };

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
