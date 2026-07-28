import { describe, expect, it } from "vitest";
import {
  LocalKeyProvider,
  generateEncryptionKey,
  generateSigningKey,
} from "@compliance-kit/crypto";
import type { AppConfig } from "@compliance-kit/config";
import type { ConnectionManager } from "@compliance-kit/db";
import { KeyRegistryService, NoActiveKeyError } from "./key-registry.service";

/**
 * What gets published, and what still verifies, is the security-relevant behaviour here. A registry
 * that publishes a revoked key, or keeps accepting one past its overlap, fails quietly: every
 * request still succeeds, which is precisely the problem.
 */

const KEK = Buffer.alloc(32, 3).toString("base64url");
const provider = new LocalKeyProvider(new Uint8Array(Buffer.from(KEK, "base64url")));

interface Row {
  kid: string;
  purpose: "token_signing" | "token_encryption";
  algorithm: string;
  state: "pending" | "active" | "retiring" | "revoked";
  wrappedKey: Buffer | null;
  kekId: string;
  publicJwk: unknown;
  notAfter: Date | null;
}

async function signingRow(state: Row["state"], notAfter: Date | null = null): Promise<Row> {
  const key = await generateSigningKey();
  const wrapped = await provider.wrap(new TextEncoder().encode(key.privatePkcs8), {
    purpose: "token_signing",
    kid: key.kid,
  });
  return {
    kid: key.kid,
    purpose: "token_signing",
    algorithm: "ES256",
    state,
    wrappedKey: Buffer.from(wrapped),
    kekId: provider.id,
    publicJwk: key.publicJwk,
    notAfter,
  };
}

async function encryptionRow(state: Row["state"], notAfter: Date | null = null): Promise<Row> {
  const key = generateEncryptionKey();
  const wrapped = await provider.wrap(key.secret, { purpose: "token_encryption", kid: key.kid });
  return {
    kid: key.kid,
    purpose: "token_encryption",
    algorithm: "A256KW",
    state,
    wrappedKey: Buffer.from(wrapped),
    kekId: provider.id,
    publicJwk: null,
    notAfter,
  };
}

/**
 * A registry over a fixed set of rows.
 *
 * The fake stands in for the master database only, so the real unwrap, import and filter logic all
 * run. Mocking at the KeyProvider level instead would skip exactly the part worth testing.
 */
async function registryOver(rows: Row[]): Promise<KeyRegistryService> {
  const cm = {
    master: {
      configKey: {
        // The service asks only for active and retiring rows; honour that so the fake cannot
        // accidentally be more permissive than production.
        findMany: () =>
          Promise.resolve(rows.filter((r) => r.state === "active" || r.state === "retiring")),
      },
    },
  } as unknown as ConnectionManager;

  const service = new KeyRegistryService({ keyEncryptionKey: KEK } as AppConfig, cm);
  await service.onModuleInit();
  return service;
}

describe("KeyRegistryService", () => {
  it("loads the active key pair and offers it as material", async () => {
    const signing = await signingRow("active");
    const encryption = await encryptionRow("active");
    const registry = await registryOver([signing, encryption]);

    const material = registry.activeMaterial();
    expect(material.signing.kid).toBe(signing.kid);
    expect(material.encryption.kid).toBe(encryption.kid);
    registry.onModuleDestroy();
  });

  // Better a loud failure at the first login than a token signed with something unintended.
  it("throws rather than improvising when there is no active key", async () => {
    const registry = await registryOver([]);
    expect(() => registry.activeMaterial()).toThrow(NoActiveKeyError);
    registry.onModuleDestroy();
  });

  it("names the command that fixes it in the error, since this is a first-run failure", async () => {
    const registry = await registryOver([await encryptionRow("active")]);
    expect(() => registry.activeMaterial()).toThrow(/keys:init/);
    registry.onModuleDestroy();
  });

  describe("resolvers", () => {
    it("resolve an active key", async () => {
      const signing = await signingRow("active");
      const registry = await registryOver([signing, await encryptionRow("active")]);
      expect(registry.resolvers().signing(signing.kid)).toBeDefined();
      registry.onModuleDestroy();
    });

    // The rotation overlap: a token signed before rotation must keep verifying.
    it("resolve a retiring key, so tokens signed before a rotation still verify", async () => {
      const retiring = await signingRow("retiring", new Date(Date.now() + 60_000));
      const registry = await registryOver([retiring, await encryptionRow("active")]);
      expect(registry.resolvers().signing(retiring.kid)).toBeDefined();
      registry.onModuleDestroy();
    });

    // not_after is honoured at the point of use rather than trusted to a sweeper. A sweeper that
    // has not run, or that failed, would otherwise leave an expired key verifying indefinitely.
    it("refuse a retiring key whose overlap has already ended", async () => {
      const expired = await signingRow("retiring", new Date(Date.now() - 1_000));
      const registry = await registryOver([expired, await encryptionRow("active")]);
      expect(registry.resolvers().signing(expired.kid)).toBeUndefined();
      registry.onModuleDestroy();
    });

    it("refuse an unknown kid", async () => {
      const registry = await registryOver([
        await signingRow("active"),
        await encryptionRow("active"),
      ]);
      expect(registry.resolvers().signing("nope")).toBeUndefined();
      expect(registry.resolvers().encryption("nope")).toBeUndefined();
      registry.onModuleDestroy();
    });

    // Structurally impossible to confuse the two, because they are separately typed and backed by
    // separate maps. Asserted anyway, because this is the substitution attack kid resolution invites.
    it("never return an encryption key from the signing resolver", async () => {
      const signing = await signingRow("active");
      const encryption = await encryptionRow("active");
      const registry = await registryOver([signing, encryption]);

      expect(registry.resolvers().signing(encryption.kid)).toBeUndefined();
      expect(registry.resolvers().encryption(signing.kid)).toBeUndefined();
      registry.onModuleDestroy();
    });

    /**
     * Synchronous, and this is the property that must not regress. jose calls resolvers with an
     * attacker-controlled kid before anything is verified, so an async resolver would let a forged
     * kid drive a database query or a KMS unwrap per request.
     */
    it("are synchronous, not thenable", async () => {
      const signing = await signingRow("active");
      const registry = await registryOver([signing, await encryptionRow("active")]);
      const resolved = registry.resolvers().signing(signing.kid);
      expect(resolved).not.toHaveProperty("then");
      registry.onModuleDestroy();
    });
  });

  describe("jwks", () => {
    it("publishes the active signing key", async () => {
      const signing = await signingRow("active");
      const registry = await registryOver([signing, await encryptionRow("active")]);
      expect(registry.jwks().keys.map((k) => k.kid)).toEqual([signing.kid]);
      registry.onModuleDestroy();
    });

    // Dropping the retiring key the moment a new one goes active would invalidate every live token
    // rather than rotating gracefully.
    it("publishes a retiring key too, so a rotation overlap is verifiable by others", async () => {
      const active = await signingRow("active");
      const retiring = await signingRow("retiring", new Date(Date.now() + 60_000));
      const registry = await registryOver([active, retiring, await encryptionRow("active")]);
      expect(
        registry
          .jwks()
          .keys.map((k) => k.kid)
          .sort(),
      ).toEqual([active.kid, retiring.kid].sort());
      registry.onModuleDestroy();
    });

    it("does not publish a retiring key past its overlap", async () => {
      const active = await signingRow("active");
      const expired = await signingRow("retiring", new Date(Date.now() - 1_000));
      const registry = await registryOver([active, expired, await encryptionRow("active")]);
      expect(registry.jwks().keys.map((k) => k.kid)).toEqual([active.kid]);
      registry.onModuleDestroy();
    });

    // The endpoint is public and unauthenticated, so anything symmetric appearing here would be a
    // disclosure of a shared secret.
    it("never publishes the symmetric encryption key", async () => {
      const encryption = await encryptionRow("active");
      const registry = await registryOver([await signingRow("active"), encryption]);
      const serialised = JSON.stringify(registry.jwks());
      expect(serialised).not.toContain(encryption.kid);
      expect(registry.jwks().keys.every((k) => k.kty === "EC")).toBe(true);
      registry.onModuleDestroy();
    });

    it("never publishes a private scalar", async () => {
      const registry = await registryOver([
        await signingRow("active"),
        await encryptionRow("active"),
      ]);
      const serialised = JSON.stringify(registry.jwks());
      expect(serialised).not.toContain('"d"');
      expect(serialised).not.toContain("PRIVATE KEY");
      registry.onModuleDestroy();
    });

    it("is an empty key set rather than an error when nothing is loaded", async () => {
      const registry = await registryOver([]);
      expect(registry.jwks()).toEqual({ keys: [] });
      registry.onModuleDestroy();
    });
  });
});
