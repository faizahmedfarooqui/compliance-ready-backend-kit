import { describe, expect, it } from "vitest";
import { LocalKeyProvider, type KeyContext } from "./key-provider";

const KEK = new Uint8Array(32).fill(3);
const OTHER_KEK = new Uint8Array(32).fill(4);
const CONTEXT: KeyContext = { purpose: "token_signing", kid: "kid-1" };
const SECRET = new TextEncoder().encode("-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----");

describe("LocalKeyProvider", () => {
  it("round-trips key material", async () => {
    const provider = new LocalKeyProvider(KEK);
    const wrapped = await provider.wrap(SECRET, CONTEXT);
    expect(await provider.unwrap(wrapped, CONTEXT)).toEqual(SECRET);
  });

  it("produces ciphertext, not a recognisable copy of the input", async () => {
    const provider = new LocalKeyProvider(KEK);
    const wrapped = await provider.wrap(SECRET, CONTEXT);
    expect(Buffer.from(wrapped).toString()).not.toContain("PRIVATE KEY");
    expect(Buffer.from(wrapped)).not.toEqual(Buffer.from(SECRET));
  });

  it("uses a fresh iv each time, so the same input wraps differently", async () => {
    const provider = new LocalKeyProvider(KEK);
    const a = await provider.wrap(SECRET, CONTEXT);
    const b = await provider.wrap(SECRET, CONTEXT);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });

  it("refuses a key-encrypting key that is not 32 bytes", () => {
    expect(() => new LocalKeyProvider(new Uint8Array(16))).toThrow(/exactly 32 bytes/);
  });

  it("reports which KEK produced a blob, so a migrated deployment can tell", () => {
    expect(new LocalKeyProvider(KEK).id).toBe("local");
    expect(new LocalKeyProvider(KEK, "kek-2024").id).toBe("kek-2024");
  });

  describe("rejects", () => {
    it("a blob wrapped under a different KEK", async () => {
      const wrapped = await new LocalKeyProvider(KEK).wrap(SECRET, CONTEXT);
      await expect(new LocalKeyProvider(OTHER_KEK).unwrap(wrapped, CONTEXT)).rejects.toThrow();
    });

    // The point of binding the context: a wrapped blob must not be interchangeable between slots.
    // Someone with write access to the registry could otherwise move a retired signing key's
    // ciphertext into the active encryption key's row and have it unwrap cleanly.
    it("a blob unwrapped under a different purpose", async () => {
      const provider = new LocalKeyProvider(KEK);
      const wrapped = await provider.wrap(SECRET, CONTEXT);
      await expect(
        provider.unwrap(wrapped, { purpose: "token_encryption", kid: "kid-1" }),
      ).rejects.toThrow();
    });

    it("a blob unwrapped under a different kid", async () => {
      const provider = new LocalKeyProvider(KEK);
      const wrapped = await provider.wrap(SECRET, CONTEXT);
      await expect(
        provider.unwrap(wrapped, { purpose: "token_signing", kid: "kid-2" }),
      ).rejects.toThrow();
    });

    it("a tampered ciphertext", async () => {
      const provider = new LocalKeyProvider(KEK);
      const wrapped = await provider.wrap(SECRET, CONTEXT);
      const tampered = Buffer.from(wrapped);
      // Flip a byte inside the ciphertext body, past the 12-byte iv.
      tampered[20] ^= 0xff;
      await expect(provider.unwrap(new Uint8Array(tampered), CONTEXT)).rejects.toThrow();
    });

    it("a tampered authentication tag", async () => {
      const provider = new LocalKeyProvider(KEK);
      const wrapped = await provider.wrap(SECRET, CONTEXT);
      const tampered = Buffer.from(wrapped);
      tampered[tampered.length - 1] ^= 0xff;
      await expect(provider.unwrap(new Uint8Array(tampered), CONTEXT)).rejects.toThrow();
    });

    it("a blob too short to contain an iv and a tag", async () => {
      const provider = new LocalKeyProvider(KEK);
      await expect(provider.unwrap(new Uint8Array(8), CONTEXT)).rejects.toThrow(/too short/);
    });
  });
});
