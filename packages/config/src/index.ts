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
      "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/problems.md",
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

  /**
   * Bearer credential for the control plane, which today means provisioning tenants.
   *
   * REQUIRED, with no default, and that is the point. An optional key would leave the route open
   * whenever it was unset, which is the state the route shipped in: `POST /api/tenants` creates
   * databases and was reachable by anyone who could open a socket. A control that is only present when
   * someone remembers to configure it is not a control, so the service refuses to boot without one.
   *
   * A shared secret, and worth being blunt about what that means. It authenticates the bearer and
   * nothing else: it does not identify WHICH operator called, it cannot be scoped to one action, it is
   * replayable by anyone who reads it from a log or a shell history, and rotating it invalidates every
   * caller at once. It is the right primitive for a kit because it needs no infrastructure, and the
   * wrong one for a mature deployment, which should use mutual TLS or a signed operator token with an
   * identity in it. Treated as a step on the way, not a destination.
   *
   * 256 bits, the same shape as the KEK, so it cannot be set to a guessable phrase.
   */
  controlPlaneApiKey: key256(),

  redisUrl: z.url(),

  /**
   * Whether to publish the OpenAPI document and the browsable UI at /docs.
   *
   * Defaults to ON, because a kit whose API is undiscoverable is a kit nobody adopts, and because the
   * spec is the honest description of the wire contract. Turn it OFF in production unless you mean to
   * publish it: an OpenAPI document is a complete map of every route, parameter and constraint, which is
   * precisely its value to an author and to an attacker. The service logs a warning when it is left on
   * with NODE_ENV=production, rather than quietly overriding the setting.
   */
  apiDocsEnabled: z
    .string()
    .optional()
    .transform((v) => v !== "false" && v !== "0")
    .pipe(z.boolean()),

  // ---------------------------------------------------------------------------
  // HTTP server limits, declared explicitly rather than inherited.
  //
  // Same reasoning as the Argon2id parameters: a value that governs a security property should have
  // one readable answer that a library upgrade cannot silently change. These four are the whole
  // request-level denial-of-service surface, so leaving them implicit means nobody can say what the
  // service actually tolerates without reading Fastify's source, which is what happened before they
  // were pinned here.
  //
  // Fastify 5.10's own defaults are requestTimeout 0, connectionTimeout 0, keepAliveTimeout 72000,
  // bodyLimit 1048576. The first two are the problem: Fastify assigns `server.requestTimeout =
  // options.requestTimeout` unconditionally, so a default of 0 does not fall back to Node's 300s, it
  // actively DISABLES the timeout Node would otherwise have applied.
  // ---------------------------------------------------------------------------

  /**
   * Milliseconds a client gets to send an entire request, headers and body.
   *
   * This is the slowloris defence, and it has to be this setting rather than a connection timeout.
   * Node's `headersTimeout` (60s, which Fastify leaves alone) already bounds a client that dribbles
   * its headers. What nothing bounded was a client that completes its headers, declares a
   * Content-Length, and then sends the body one byte at a time: no individual gap is suspicious, no
   * inactivity timeout fires, and the connection is held open for as long as the attacker likes.
   * Multiply by the connection limit and the server is out of sockets.
   *
   * 30s is generous for this API, whose bodies are small JSON documents. RAISE IT if you add file
   * upload: a 1 MiB body over a slow mobile link legitimately takes minutes, and this setting will
   * cut it off.
   */
  requestTimeoutMs: z.coerce.number().int().positive().default(30_000),

  /**
   * Socket inactivity timeout (Node's `server.setTimeout`).
   *
   * Deliberately ABOVE keepAliveTimeout, and that ordering is the whole point. This is a backstop for
   * a socket that is neither mid-request nor a recognised idle keep-alive, so it must not preempt the
   * keep-alive timeout: set it lower and it silently becomes the rule that governs idle connections,
   * making keepAliveTimeoutMs dead config and reintroducing the load-balancer race described below.
   */
  connectionTimeoutMs: z.coerce.number().int().positive().default(75_000),

  /**
   * How long an idle keep-alive connection is kept.
   *
   * Longer than it looks like it should be, on purpose. This must EXCEED the idle timeout of whatever
   * sits in front of the service, because if the proxy reuses a socket the server has just closed,
   * the client gets a 502 that appears in no application log. AWS ALB idles at 60s by default, hence
   * 72s here, which is also Fastify's default. Lower it only after lowering the proxy's.
   */
  keepAliveTimeoutMs: z.coerce.number().int().positive().default(72_000),

  /** Maximum request body in bytes. Fastify's own default, pinned so it cannot drift. */
  bodyLimitBytes: z.coerce.number().int().positive().default(1_048_576),

  /**
   * How often Node sweeps in-flight requests looking for expired ones.
   *
   * This is the granularity of `requestTimeoutMs`, not a separate limit. Node does not arm a timer per
   * request; it walks the connection list on an interval and destroys whatever has overstayed, so the
   * effective deadline is the timeout PLUS up to one interval. Node's own default is 30s, which would
   * make a 30s request timeout fire anywhere between 30s and 60s.
   *
   * 5s trades one unref'd interval timer for enforcement that is within 5s of the deadline. The sweep
   * itself is a native walk over the connection list, so the cost does not scale with request volume,
   * only with concurrent connections.
   */
  connectionsCheckingIntervalMs: z.coerce.number().int().positive().default(5_000),

  // ---------------------------------------------------------------------------
  // Rate limiting.
  // ---------------------------------------------------------------------------

  /**
   * Whether to believe `X-Forwarded-For`.
   *
   * This single boolean decides whether rate limiting works at all, and BOTH settings are wrong in
   * some deployment, so it has to be a deliberate choice rather than a default anyone can ignore.
   *
   * Left false behind a load balancer, every request appears to come from the balancer's address, so
   * all of your traffic shares one bucket and the first busy client rate-limits everybody. Set true
   * without a trusted proxy in front, and a caller simply sends `X-Forwarded-For: <anything>` to get
   * a fresh bucket per request, which defeats the control silently.
   *
   * The default is false because that failure is loud (everyone gets 429s, you notice within
   * minutes) whereas the other is silent (the limiter reports healthy and enforces nothing). Turn it
   * on when, and only when, something you control is appending the header.
   */
  trustProxy: z
    .string()
    .optional()
    .transform((v) => v === "true" || v === "1")
    .pipe(z.boolean()),

  /** Requests allowed per client per window, for routes with no explicit limit of their own. */
  rateLimitDefaultLimit: z.coerce.number().int().positive().default(100),
  rateLimitDefaultWindowMs: z.coerce.number().int().positive().default(60_000),

  /**
   * Failed logins allowed per account, and per source address, before both are throttled.
   *
   * Counted on FAILURE only and cleared on success, so an ordinary user who mistypes twice and then
   * succeeds is never nearer a limit. Ten in fifteen minutes leaves room for a forgotten password
   * while removing any useful rate of guessing.
   */
  loginThrottleLimit: z.coerce.number().int().positive().default(10),
  loginThrottleWindowMs: z.coerce.number().int().positive().default(900_000),

  /**
   * What to do when Redis cannot be reached: serve the request (true) or reject it (false).
   *
   * Fails OPEN by default, and this is a real trade rather than an oversight. Closed turns a Redis
   * blip into a total outage of the whole API, including the login route, which is a bigger incident
   * than the one being prevented. Open means that during an outage there is no rate limiting, which
   * is why every occurrence is logged at error level: the control degrades visibly rather than
   * quietly.
   *
   * Set false where unmetered access is the greater risk, and accept that Redis then becomes a
   * hard dependency for serving traffic.
   */
  rateLimitFailOpen: z
    .string()
    .optional()
    .transform((v) => v !== "false" && v !== "0")
    .pipe(z.boolean()),
});

/**
 * The two timeouts interact, so the ordering is checked at boot rather than trusted to the comments
 * above. A deployment that lowers connectionTimeoutMs below keepAliveTimeoutMs would still start and
 * still serve traffic, while quietly governing idle connections by the wrong rule; that is precisely
 * the class of misconfiguration this file exists to refuse.
 */
const withInvariants = schema
  .refine((c) => c.connectionTimeoutMs > c.keepAliveTimeoutMs, {
    message:
      "CONNECTION_TIMEOUT_MS must be greater than KEEP_ALIVE_TIMEOUT_MS, or the socket inactivity " +
      "timeout preempts the keep-alive timeout and becomes the rule that governs idle connections",
    path: ["connectionTimeoutMs"],
  })
  .refine((c) => c.connectionsCheckingIntervalMs < c.requestTimeoutMs, {
    message:
      "CONNECTIONS_CHECKING_INTERVAL_MS must be less than REQUEST_TIMEOUT_MS, or the sweep " +
      "granularity rather than the timeout decides when a slow request is cut off",
    path: ["connectionsCheckingIntervalMs"],
  });

export type AppConfig = z.infer<typeof withInvariants>;

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
  const parsed = withInvariants.safeParse({
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
    controlPlaneApiKey: source.CONTROL_PLANE_API_KEY,
    redisUrl: source.REDIS_URL,
    apiDocsEnabled: source.API_DOCS_ENABLED,
    requestTimeoutMs: source.REQUEST_TIMEOUT_MS,
    connectionTimeoutMs: source.CONNECTION_TIMEOUT_MS,
    keepAliveTimeoutMs: source.KEEP_ALIVE_TIMEOUT_MS,
    bodyLimitBytes: source.BODY_LIMIT_BYTES,
    connectionsCheckingIntervalMs: source.CONNECTIONS_CHECKING_INTERVAL_MS,
    trustProxy: source.TRUST_PROXY,
    rateLimitDefaultLimit: source.RATE_LIMIT_DEFAULT_LIMIT,
    rateLimitDefaultWindowMs: source.RATE_LIMIT_DEFAULT_WINDOW_MS,
    loginThrottleLimit: source.LOGIN_THROTTLE_LIMIT,
    loginThrottleWindowMs: source.LOGIN_THROTTLE_WINDOW_MS,
    rateLimitFailOpen: source.RATE_LIMIT_FAIL_OPEN,
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
