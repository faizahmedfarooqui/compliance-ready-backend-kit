import { describe, expect, it } from "vitest";
import { loadConfig } from "./index";

/**
 * Config is the last place a bad value can be stopped cheaply. Everything below is a boot-time
 * failure that would otherwise become a runtime one, and the key checks in particular are load
 * bearing: `jose` will happily sign with a 4-byte key, so if this schema does not enforce the
 * length nothing downstream will.
 */

const KEK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function validEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    MASTER_DATABASE_URL: "postgres://postgres:postgres@localhost:55432/master",
    TENANT_CLUSTER_URL: "postgres://postgres:postgres@localhost:55432",
    JWT_ISSUER: "test-issuer",
    JWT_AUDIENCE: "test-audience",
    KEY_ENCRYPTION_KEY: KEK,
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

  it("names the offending field in the error, so a bad deploy is diagnosable", () => {
    expect(() => loadConfig(validEnv({ REDIS_URL: undefined }))).toThrow(/redisUrl/);
  });
});
