import { describe, expect, it } from "vitest";
import { loadConfig } from "./index";

/**
 * Config is the last place a bad value can be stopped cheaply. Everything below is a boot-time
 * failure that would otherwise become a runtime one, and the key checks in particular are load
 * bearing: `jose` will happily sign with a 4-byte key, so if this schema does not enforce the
 * length nothing downstream will.
 */

const KEK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CP_KEY = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

function validEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    MASTER_DATABASE_URL: "postgres://postgres:postgres@localhost:55432/master",
    TENANT_CLUSTER_URL: "postgres://postgres:postgres@localhost:55432",
    JWT_ISSUER: "test-issuer",
    JWT_AUDIENCE: "test-audience",
    KEY_ENCRYPTION_KEY: KEK,
    CONTROL_PLANE_API_KEY: CP_KEY,
    REDIS_URL: "redis://localhost:56379",
    ...overrides,
  };
}

describe("loadConfig", () => {
  it("accepts a complete configuration", () => {
    const config = loadConfig(validEnv());
    expect(config.jwtIssuer).toBe("test-issuer");
    expect(config.masterDatabaseUrl).toContain("localhost:55432");
  });

  it("applies defaults for the optional values", () => {
    const config = loadConfig(validEnv());
    expect(config.nodeEnv).toBe("development");
    // Deliberately not 3000/3001, which collide with almost every other dev server.
    expect(config.port).toBe(3011);
    expect(config.jwtAccessTtlSeconds).toBe(900);
    // Errors cite this base URI as their RFC 9457 `type`, so it must have a usable default.
    expect(config.problemTypeBaseUri).toMatch(/^https:\/\//);
  });

  it("coerces numeric values that arrive as strings, because env vars always do", () => {
    const config = loadConfig(validEnv({ PORT: "8080", JWT_ACCESS_TTL_SECONDS: "60" }));
    expect(config.port).toBe(8080);
    expect(config.jwtAccessTtlSeconds).toBe(60);
  });

  describe("rejects", () => {
    it.each([
      ["MASTER_DATABASE_URL", undefined],
      ["TENANT_CLUSTER_URL", undefined],
      ["JWT_ISSUER", undefined],
      ["JWT_AUDIENCE", undefined],
      ["KEY_ENCRYPTION_KEY", undefined],
      ["CONTROL_PLANE_API_KEY", undefined],
      ["REDIS_URL", undefined],
    ])("a missing %s", (name) => {
      expect(() => loadConfig(validEnv({ [name]: undefined }))).toThrow(/Invalid configuration/);
    });

    it("a database url that is not a url", () => {
      expect(() => loadConfig(validEnv({ MASTER_DATABASE_URL: "not-a-url" }))).toThrow(
        /Invalid configuration/,
      );
    });

    // A "minimum 16 characters" check would accept a 128-bit secret. AES-256-GCM, which the local
    // key provider wraps with, needs exactly 256 bits, and nothing downstream re-checks.
    it("a key-encrypting key shorter than 256 bits", () => {
      expect(() => loadConfig(validEnv({ KEY_ENCRYPTION_KEY: "tooshort" }))).toThrow(
        /base64url-encoded 256-bit key/,
      );
    });

    it("a key containing characters that are not base64url", () => {
      // Right length, wrong alphabet: '+' and '/' are base64, not base64url.
      const notBase64Url = `${"A".repeat(41)}+/`;
      expect(() => loadConfig(validEnv({ KEY_ENCRYPTION_KEY: notBase64Url }))).toThrow(
        /base64url-encoded 256-bit key/,
      );
    });

    it("an unrecognised NODE_ENV", () => {
      expect(() => loadConfig(validEnv({ NODE_ENV: "staging" }))).toThrow(/Invalid configuration/);
    });

    it("a non-positive port", () => {
      expect(() => loadConfig(validEnv({ PORT: "0" }))).toThrow(/Invalid configuration/);
    });
  });

  /**
   * There used to be a cross-field rule here forbidding the signing and encryption keys from being
   * the same value. It is gone because those keys are gone: they live in the `config_keys` registry
   * now, generated independently by `pnpm keys:init`, so config cannot conflate them. The rule
   * itself did not disappear, it moved to where the keys are: `assertMaterial` in
   * packages/crypto/src/tokens.ts rejects material whose two kids match, and the database pairs
   * purpose to algorithm with a CHECK constraint.
   */
  it("no longer carries the token keys at all, only the KEK that wraps them", () => {
    const config = loadConfig(validEnv());
    expect(config.keyEncryptionKey).toBe(KEK);
    expect(config).not.toHaveProperty("jwtSigningKey");
    expect(config).not.toHaveProperty("jwtEncryptionKey");
  });

  it("defaults the clock tolerance, which also sets the key-rotation overlap", () => {
    expect(loadConfig(validEnv()).jwtClockToleranceSeconds).toBe(5);
    expect(
      loadConfig(validEnv({ JWT_CLOCK_TOLERANCE_SECONDS: "30" })).jwtClockToleranceSeconds,
    ).toBe(30);
  });

  /**
   * The control-plane key must be REQUIRED, never defaulted. POST /api/tenants creates databases and
   * was unauthenticated before this key existed; a default would silently restore that state for anyone
   * who did not set one, and the whole point is that the service refuses to run without it.
   */
  it("refuses to start without a control-plane key, rather than defaulting to one", () => {
    expect(() => loadConfig(validEnv({ CONTROL_PLANE_API_KEY: undefined }))).toThrow(
      /controlPlaneApiKey/,
    );
  });

  it("requires the control-plane key to be a full 256 bits, not a memorable phrase", () => {
    expect(() => loadConfig(validEnv({ CONTROL_PLANE_API_KEY: "letmein" }))).toThrow(
      /base64url-encoded 256-bit key/,
    );
  });

  // Sharing one value would mean a leaked operator credential also unwraps every token key.
  it("keeps the control-plane key separate from the KEK", () => {
    const config = loadConfig(validEnv());
    expect(config.controlPlaneApiKey).toBe(CP_KEY);
    expect(config.controlPlaneApiKey).not.toBe(config.keyEncryptionKey);
  });

  it("names the offending field in the error, so a bad deploy is diagnosable", () => {
    expect(() => loadConfig(validEnv({ REDIS_URL: undefined }))).toThrow(/redisUrl/);
  });

  /**
   * The HTTP limits are denial-of-service controls, so their defaults are asserted rather than
   * assumed. Fastify's own defaults for the first two are 0, which does not mean "use Node's
   * default": Fastify assigns them to the Node server unconditionally, so 0 disables the timeout
   * outright. That is the hole these values close, and a silent revert to 0 would reopen it.
   */
  describe("HTTP limits", () => {
    it("bounds the time a client gets to send a whole request", () => {
      expect(loadConfig(validEnv()).requestTimeoutMs).toBe(30_000);
    });

    it("pins the keep-alive and body limits rather than inheriting them", () => {
      const config = loadConfig(validEnv());
      // Above the 60s an AWS ALB idles at, so the proxy never reuses a socket we just closed.
      expect(config.keepAliveTimeoutMs).toBe(72_000);
      expect(config.bodyLimitBytes).toBe(1_048_576);
    });

    it("keeps the socket inactivity timeout above the keep-alive timeout", () => {
      const config = loadConfig(validEnv());
      expect(config.connectionTimeoutMs).toBeGreaterThan(config.keepAliveTimeoutMs);
    });

    /**
     * The ordering is an invariant, not a preference. Inverted, the inactivity timeout silently
     * becomes the rule governing idle connections, keepAliveTimeoutMs stops meaning anything, and the
     * load-balancer race it exists to prevent comes back as intermittent 502s that appear in no
     * application log. Cheaper to refuse at boot.
     */
    it("refuses to start when that ordering is inverted", () => {
      expect(() =>
        loadConfig(validEnv({ CONNECTION_TIMEOUT_MS: "10000", KEEP_ALIVE_TIMEOUT_MS: "72000" })),
      ).toThrow(/CONNECTION_TIMEOUT_MS must be greater than KEEP_ALIVE_TIMEOUT_MS/);
    });

    it("accepts an override that respects the ordering", () => {
      const config = loadConfig(
        validEnv({ CONNECTION_TIMEOUT_MS: "20000", KEEP_ALIVE_TIMEOUT_MS: "15000" }),
      );
      expect(config.connectionTimeoutMs).toBe(20_000);
      expect(config.keepAliveTimeoutMs).toBe(15_000);
    });

    // Zero is the specific value that means "disabled", so it must not be settable by accident.
    it("refuses a zero or negative timeout, which would mean no timeout at all", () => {
      expect(() => loadConfig(validEnv({ REQUEST_TIMEOUT_MS: "0" }))).toThrow(
        /Invalid configuration/,
      );
      expect(() => loadConfig(validEnv({ BODY_LIMIT_BYTES: "-1" }))).toThrow(
        /Invalid configuration/,
      );
    });
  });
});
