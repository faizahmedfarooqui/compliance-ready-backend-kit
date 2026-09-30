import { describe, expect, it } from "vitest";
import { generateEncryptionKey, generateSigningKey } from "./key-material";
import { LocalKeyProvider } from "./key-provider";
import { isKeyUsable, loadStoredKey, type StoredKeyRow } from "./key-loading";

/**
 * Every refusal here is a row that a write to the database could produce without the KEK. The point
 * of the loader is that none of them reaches a verifier or the JWKS.
 */

const provider = new LocalKeyProvider(new Uint8Array(32).fill(7));

async function signingRow(): Promise<StoredKeyRow> {
  const key = await generateSigningKey();
  return {
    kid: key.kid,
    purpose: "token_signing",
    algorithm: "ES256",
    wrappedKey: await provider.wrap(new TextEncoder().encode(key.privatePkcs8), {
      purpose: "token_signing",
      kid: key.kid,
    }),
    kekId: provider.id,
    publicJwk: key.publicJwk,
  };
}

async function encryptionRow(secret = generateEncryptionKey().secret): Promise<StoredKeyRow> {
  const kid = generateEncryptionKey().kid;
  return {
    kid,
    purpose: "token_encryption",
    algorithm: "A256KW",
    wrappedKey: await provider.wrap(secret, { purpose: "token_encryption", kid }),
    kekId: provider.id,
    publicJwk: null,
  };
}

const jwkOf = (row: StoredKeyRow) => row.publicJwk as Record<string, unknown>;

describe("loadStoredKey", () => {
  it("loads a signing key and publishes a JWK built only from verified parts", async () => {
    const row = await signingRow();
    // A harmless extra member in storage must not reach the JWKS: what is published is constructed.
    row.publicJwk = { ...jwkOf(row), note: "added by hand" };
    const loaded = await loadStoredKey(provider, row);
    expect(loaded.purpose).toBe("token_signing");
    if (loaded.purpose !== "token_signing") return;
    expect(Object.keys(loaded.publicJwk).sort()).toEqual([
      "alg",
      "crv",
      "kid",
      "kty",
      "use",
      "x",
      "y",
    ]);
    expect(loaded.publicJwk).toMatchObject({ kid: row.kid, alg: "ES256", use: "sig" });
  });

  it("loads an encryption key", async () => {
    const loaded = await loadStoredKey(provider, await encryptionRow());
    expect(loaded.purpose).toBe("token_encryption");
    if (loaded.purpose === "token_encryption") expect(loaded.secret.byteLength).toBe(32);
  });

  describe("refuses", () => {
    it("another key pair's public JWK wearing this row's kid", async () => {
      const row = await signingRow();
      const other = await generateSigningKey();
      row.publicJwk = { ...other.publicJwk, kid: row.kid };
      await expect(loadStoredKey(provider, row)).rejects.toThrow(/not the public half/);
    });

    // The metadata case: right key material, wrong kid. Published verbatim, it would give external
    // verifiers a kid that no token carries, so every token signed under the row's kid would fail there.
    it("a public JWK whose kid is not the row's own", async () => {
      const row = await signingRow();
      row.publicJwk = { ...jwkOf(row), kid: "something-else" };
      await expect(loadStoredKey(provider, row)).rejects.toThrow(/names kid "something-else"/);
    });

    it.each([
      ["an alg other than ES256", { alg: "RS256" }, /declares alg "RS256"/],
      ["a use other than sig", { use: "enc" }, /declares use "enc"/],
      ["a private scalar", { d: "AAAA" }, /carries private members \(d\)/],
    ])("a public JWK with %s", async (_label, change, message) => {
      const row = await signingRow();
      row.publicJwk = { ...jwkOf(row), ...change };
      await expect(loadStoredKey(provider, row)).rejects.toThrow(message);
    });

    it("a row wrapped by a key-encrypting key this process does not hold", async () => {
      const row = await signingRow();
      row.kekId = "kms:some-other-kek";
      await expect(loadStoredKey(provider, row)).rejects.toThrow(/kms:some-other-kek/);
    });

    it("a row whose algorithm does not match its purpose", async () => {
      const row = await signingRow();
      row.algorithm = "A256KW";
      await expect(loadStoredKey(provider, row)).rejects.toThrow(/must be ES256/);
    });

    it("a corrupted wrapped key", async () => {
      const row = await signingRow();
      const blob = Buffer.from(row.wrappedKey ?? []);
      blob[20] ^= 0xff;
      row.wrappedKey = blob;
      await expect(loadStoredKey(provider, row)).rejects.toThrow();
    });

    it("an encryption key of the wrong length", async () => {
      await expect(
        loadStoredKey(provider, await encryptionRow(new Uint8Array(16))),
      ).rejects.toThrow(/must be 32 bytes/);
    });

    it("a row with no material", async () => {
      const row = await signingRow();
      row.wrappedKey = null;
      await expect(loadStoredKey(provider, row)).rejects.toThrow(/no key material/);
    });
  });
});

describe("isKeyUsable", () => {
  const now = Date.parse("2026-09-30T12:00:00Z");
  it.each([
    ["active with no end", { state: "active", notAfter: null }, true],
    ["retiring inside its overlap", { state: "retiring", notAfter: new Date(now + 1000) }, true],
    ["retiring past its overlap", { state: "retiring", notAfter: new Date(now - 1000) }, false],
    ["at exactly its end", { state: "retiring", notAfter: new Date(now) }, false],
    ["revoked", { state: "revoked", notAfter: null }, false],
    ["pending", { state: "pending", notAfter: null }, false],
  ])("%s", (_label, key, expected) => {
    expect(isKeyUsable(key, now)).toBe(expected);
  });
});
