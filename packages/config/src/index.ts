import { existsSync } from "node:fs";
import path from "node:path";
import { config as readDotenvFile } from "dotenv";
import { z } from "zod";

/**
 * Typed, validated configuration. Fails fast at boot on a missing or malformed value,
 * so a misconfigured deploy never starts.
 *
 * SECRETS NOTE: `loadConfig` reads from a plain record (process.env in local dev).
 * In production, resolve secrets (DB passwords, the JWT signing key) from KMS /
 * Secrets Manager FIRST, merge them into the record you pass here, and never leave
 * them in process.env at runtime. `loadConfig` is the single validated entry point;
 * swap the source, not the shape. See COMPLIANCE.md (secrets management).
 */
/** Base64url with no padding: exactly 43 characters encodes exactly 32 bytes. */
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

/**
 * A 256-bit key, base64url encoded.
 *
 * Encoded rather than a passphrase because the algorithms require an exact key length
 * (A256KW takes a 256-bit key; HS256 wants at least its 256-bit hash size, and RFC 7518
 * section 3.2 requires it). A "minimum 16 characters" string check would happily accept a
 * 128-bit secret, and `jose` does not enforce the minimum itself: it will sign with a
 * 4-byte key without complaint. So the length is pinned here, where it fails at boot.
 *
 * Generate one with:
 *   node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
 */
function key256(): z.ZodString {
  return z.string().regex(BASE64URL_32_BYTES, {
    message:
      "must be a base64url-encoded 256-bit key (43 chars). Generate with: " +
      `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`,
  });
}

const schema = z.object({
  nodeEnv: z.enum(["development", "test", "production"]).default("development"),
  // Deliberately not 3000/3001: those collide with almost every other dev server.
  port: z.coerce.number().int().positive().default(3011),

  masterDatabaseUrl: z.url(),
  tenantClusterUrl: z.url(),

  /**
   * Base URI for RFC 9457 `type` values; the problem code is appended as a fragment.
   * RFC 9457 §3.1.1 recommends an absolute URI and says dereferencing it SHOULD yield
   * human-readable documentation, so this points at the error catalogue. Override it if you
   * fork the kit, otherwise your API will cite someone else's docs for its own errors.
   */
  problemTypeBaseUri: z
    .url()
    .default(
      "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/docs/problems.md",
    ),

  jwtIssuer: z.string().min(1),
  /** Rejects a token minted for a different service that happens to share our keys. */
  jwtAudience: z.string().min(1),
  jwtAccessTtlSeconds: z.coerce.number().int().positive().default(900),

  /**
   * Leeway for clock skew when validating `exp` and `iat`, in seconds.
   *
   * Also sets the length of a key-rotation overlap, since a retiring key must stay verifiable for
   * as long as a token it signed can still be presented: TTL plus this tolerance.
   */
  jwtClockToleranceSeconds: z.coerce.number().int().nonnegative().default(5),

  /**
   * The key-encrypting key (KEK), and now the ONLY key in configuration.
   *
   * The token signing and encryption keys used to live here. They moved into the `config_keys`
   * registry in the master database, where they are stored wrapped by this key. That is the point
   * of envelope encryption: a key in config is a key in every deploy manifest, CI secret store and
   * developer shell, whereas one KEK can be moved into KMS, an HSM or an enclave without touching
   * the rest of the system. See packages/crypto/src/key-provider.ts.
   *
   * When a KMS adapter is configured this becomes unnecessary; until then it is what the local
   * provider wraps with.
   */
  keyEncryptionKey: key256(),

  redisUrl: z.url(),
});

export type AppConfig = z.infer<typeof schema>;

/**
 * Find the nearest `.env` walking up from `startDir`. A service is started from its own
 * directory (`services/auth`) but the developer's `.env` lives at the repo root, so
 * neither location alone is reliable.
 */
function findDotenvFile(startDir: string, maxLevels = 5): string | undefined {
  let dir = startDir;
  for (let level = 0; level < maxLevels; level += 1) {
    const candidate = path.join(dir, ".env");
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

/**
 * Populate process.env from a local `.env` file, for LOCAL DEVELOPMENT ONLY.
 *
 * This is a developer-experience shim, not the production secrets path. It is skipped
 * entirely when NODE_ENV=production, where the database URL and JWT signing key are
 * expected to arrive from KMS / Secrets Manager and be handed to `loadConfig` directly.
 * dotenv never overwrites a variable that is already set, so a real environment always
 * wins over the file.
 */
export function loadLocalDotenv(): void {
  if (process.env.NODE_ENV === "production") return;
  const envFile = findDotenvFile(process.cwd());
  if (!envFile) return;
  readDotenvFile({ path: envFile, quiet: true });
}

/** Build config from a raw source (default: process.env), validating the shape. */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = schema.safeParse({
    nodeEnv: source.NODE_ENV,
    port: source.PORT,
    masterDatabaseUrl: source.MASTER_DATABASE_URL,
    tenantClusterUrl: source.TENANT_CLUSTER_URL,
    problemTypeBaseUri: source.PROBLEM_TYPE_BASE_URI,
    jwtIssuer: source.JWT_ISSUER,
    jwtAudience: source.JWT_AUDIENCE,
    jwtAccessTtlSeconds: source.JWT_ACCESS_TTL_SECONDS,
    jwtClockToleranceSeconds: source.JWT_CLOCK_TOLERANCE_SECONDS,
    // In production the KEK is injected from KMS / Secrets Manager, not read from env.
    keyEncryptionKey: source.KEY_ENCRYPTION_KEY,
    redisUrl: source.REDIS_URL,
  });

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new Error(
      `Invalid configuration:\n${issues}\n\n` +
        `For local development, copy .env.example to .env at the repo root.`,
    );
  }
  return parsed.data;
}
