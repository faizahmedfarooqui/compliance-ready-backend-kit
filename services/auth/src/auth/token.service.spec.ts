import { describe, expect, it, vi } from "vitest";
import {
  generateEncryptionKey,
  generateSigningKey,
  importSigningKey,
  importVerificationKey,
  issueNestedToken,
  type TokenMaterial,
  type TokenPolicy,
  type TokenResolvers,
} from "@compliance-kit/crypto";
import { InvalidAccessTokenError } from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import type { KeyRegistryService } from "../keys/key-registry.service";
import { TokenService } from "./token.service";

/**
 * What is under test here is the retry, not the codec.
 *
 * `verify` makes two attempts with a registry refresh in between, so that a key rotated a moment ago
 * does not reject every live token until the instance restarts. That retry has to distinguish two
 * kinds of failure: a token that does not verify, which is a 401, and a bug in our own code, which is
 * a 500. Collapsing the second into the first hides server faults behind a status nobody investigates.
 */

const CONFIG = {
  jwtIssuer: "test-issuer",
  jwtAudience: "test-audience",
  jwtAccessTtlSeconds: 900,
  jwtClockToleranceSeconds: 5,
} as AppConfig;

const CLAIMS = {
  sub: "11111111-1111-4111-8111-111111111111",
  tid: "22222222-2222-4222-8222-222222222222",
  roles: ["tenant-admin"],
  permissions: ["users:read"],
};

/** Mirrors what the service derives from CONFIG, so an issued token is one it would accept. */
const POLICY: TokenPolicy = {
  issuer: CONFIG.jwtIssuer,
  audience: CONFIG.jwtAudience,
  ttlSeconds: CONFIG.jwtAccessTtlSeconds,
  clockToleranceSeconds: CONFIG.jwtClockToleranceSeconds,
};

/** Real key material, so a token that should verify actually does. */
async function material(): Promise<{ material: TokenMaterial; resolvers: TokenResolvers }> {
  const signing = await generateSigningKey();
  const encryption = generateEncryptionKey();
  const privateKey = await importSigningKey(signing.privatePkcs8);
  const publicKey = await importVerificationKey(signing.publicJwk);

  return {
    material: {
      signing: { kid: signing.kid, key: privateKey },
      encryption: { kid: encryption.kid, key: encryption.secret },
    },
    resolvers: {
      signing: (kid) => (kid === signing.kid ? publicKey : undefined),
      encryption: (kid) => (kid === encryption.kid ? encryption.secret : undefined),
    },
  };
}

/** Resolvers that know nothing, so verification fails the way an unknown kid would. */
const NO_KEYS: TokenResolvers = { signing: () => undefined, encryption: () => undefined };

/**
 * A registry stub whose `resolvers()` behaviour is scripted per call, which is what lets a failure be
 * injected into the second attempt specifically.
 */
function registry(script: (() => TokenResolvers)[]): {
  service: KeyRegistryService;
  refreshes: () => number;
} {
  let call = 0;
  let refreshes = 0;
  const stub = {
    resolvers: () => {
      const step = script[Math.min(call, script.length - 1)];
      call += 1;
      return step();
    },
    refreshIfStale: () => {
      refreshes += 1;
      return Promise.resolve();
    },
  };
  return { service: stub as unknown as KeyRegistryService, refreshes: () => refreshes };
}

describe("TokenService.verify", () => {
  it("returns the claims for a token that verifies on the first attempt", async () => {
    const { material: m, resolvers } = await material();
    const token = await issueNestedToken(CLAIMS, m, POLICY);
    const { service } = registry([() => resolvers]);
    const tokens = new TokenService(CONFIG, service);

    await expect(tokens.verify(token)).resolves.toEqual(CLAIMS);
  });

  it("collapses a verification failure into InvalidAccessTokenError, telling the caller nothing", async () => {
    const { material: m } = await material();
    const token = await issueNestedToken(CLAIMS, m, POLICY);
    const { service, refreshes } = registry([() => NO_KEYS]);
    const tokens = new TokenService(CONFIG, service);

    await expect(tokens.verify(token)).rejects.toThrow(InvalidAccessTokenError);
    // It did try a refresh first, which is the rotation case.
    expect(refreshes()).toBe(1);
  });

  /**
   * The retry exists for exactly this: an operator rotated a key, this instance's snapshot predates
   * it, and the first attempt fails on an unrecognised kid. After the refresh the same token verifies.
   */
  it("succeeds on the retry once a refresh has taught the registry the new key", async () => {
    const { material: m, resolvers } = await material();
    const token = await issueNestedToken(CLAIMS, m, POLICY);
    const { service, refreshes } = registry([() => NO_KEYS, () => resolvers]);
    const tokens = new TokenService(CONFIG, service);

    await expect(tokens.verify(token)).resolves.toEqual(CLAIMS);
    expect(refreshes()).toBe(1);
  });

  describe("does not disguise a server fault as a 401", () => {
    // `resolvers()` is called outside the codec's own try/catch, so a registry in a bad state throws
    // a plain Error through it. That is a bug in our code, not a bad token.
    it("rethrows a non-verification error from the FIRST attempt", async () => {
      const boom = new TypeError("registry exploded");
      const { service, refreshes } = registry([
        () => {
          throw boom;
        },
      ]);
      const tokens = new TokenService(CONFIG, service);

      await expect(tokens.verify("any-token")).rejects.toBe(boom);
      // Never even got to the retry, so nothing was refreshed.
      expect(refreshes()).toBe(0);
    });

    /**
     * The regression this file was written for. The second attempt used to catch everything and throw
     * InvalidAccessTokenError, so a TypeError on the retry path surfaced as a 401 and never reached
     * error monitoring. The refresh in between is what makes it reachable: the second call runs
     * against a different snapshot and can fail in ways the first did not.
     */
    it("rethrows a non-verification error from the RETRY, not InvalidAccessTokenError", async () => {
      const boom = new TypeError("registry exploded after the refresh");
      const { service, refreshes } = registry([
        () => NO_KEYS,
        () => {
          throw boom;
        },
      ]);
      const tokens = new TokenService(CONFIG, service);

      await expect(tokens.verify("any-token")).rejects.toBe(boom);
      await expect(tokens.verify("any-token")).rejects.not.toBeInstanceOf(InvalidAccessTokenError);
      expect(refreshes()).toBeGreaterThan(0);
    });
  });

  it("rejects a token whose claims verify but are the wrong shape", async () => {
    const { material: m, resolvers } = await material();
    // roles as a string rather than an array of strings: signed by us, still not usable.
    const token = await issueNestedToken({ ...CLAIMS, roles: "tenant-admin" }, m, POLICY);
    const { service } = registry([() => resolvers]);
    const tokens = new TokenService(CONFIG, service);

    await expect(tokens.verify(token)).rejects.toThrow(InvalidAccessTokenError);
  });

  it("does not retry more than once, so a persistent failure cannot loop", async () => {
    const resolvers = vi.fn(() => NO_KEYS);
    const stub = {
      resolvers,
      refreshIfStale: () => Promise.resolve(),
    } as unknown as KeyRegistryService;
    const tokens = new TokenService(CONFIG, stub);

    await expect(tokens.verify("any-token")).rejects.toThrow(InvalidAccessTokenError);
    expect(resolvers).toHaveBeenCalledTimes(2);
  });
});
