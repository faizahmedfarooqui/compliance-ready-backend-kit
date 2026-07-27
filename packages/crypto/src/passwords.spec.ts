import { describe, expect, it } from "vitest";
import {
  ARGON2_OPTIONS,
  hashPassword,
  needsRehash,
  verifyAgainstDecoy,
  verifyPassword,
} from "./passwords";

describe("ARGON2_OPTIONS", () => {
  // Pinned deliberately: an assessor asking "what KDF, at what work factor" should get one
  // readable answer, and a dependency upgrade must not silently change it. If you intend to raise
  // these, change them here and update this test in the same commit.
  it("states the cost parameters explicitly rather than inheriting library defaults", () => {
    expect(ARGON2_OPTIONS).toMatchObject({ memoryCost: 19456, timeCost: 2, parallelism: 1 });
  });

  it("uses argon2id, not argon2i or argon2d", () => {
    // argon2id is 2 in the library's enum.
    expect(ARGON2_OPTIONS.type).toBe(2);
  });
});

describe("hashPassword / verifyPassword", () => {
  it("round-trips a password", async () => {
    const hash = await hashPassword("correct-horse-battery-staple");
    await expect(verifyPassword(hash, "correct-horse-battery-staple")).resolves.toBe(true);
  });

  it("rejects the wrong password", async () => {
    const hash = await hashPassword("correct-horse-battery-staple");
    await expect(verifyPassword(hash, "wrong-password-entirely")).resolves.toBe(false);
  });

  it("salts, so the same password hashes differently every time", async () => {
    const [a, b] = await Promise.all([
      hashPassword("same-password"),
      hashPassword("same-password"),
    ]);
    expect(a).not.toBe(b);
  });

  it("encodes the chosen parameters into the digest", async () => {
    const hash = await hashPassword("whatever-it-is-here");
    expect(hash).toMatch(/^\$argon2id\$v=19\$/);
    // Asserted individually rather than as one substring: the PHC string orders these m,p,t, and
    // pinning the order would make this test fail on a formatting change that harms nothing.
    expect(hash).toMatch(/\bm=19456\b/);
    expect(hash).toMatch(/\bt=2\b/);
    expect(hash).toMatch(/\bp=1\b/);
  });

  // A corrupt row should be a failed login, not a 500.
  it("returns false rather than throwing on a malformed digest", async () => {
    await expect(verifyPassword("not-a-hash", "anything")).resolves.toBe(false);
    await expect(verifyPassword("", "anything")).resolves.toBe(false);
  });
});

describe("needsRehash", () => {
  it("is false for a hash produced with the current parameters", async () => {
    const hash = await hashPassword("current-parameters-pw");
    expect(needsRehash(hash)).toBe(false);
  });

  // The point of the feature: raising the work factor must upgrade existing credentials on next
  // login, or only new passwords ever benefit.
  it("is true for a hash produced with weaker parameters", async () => {
    const argon2 = await import("argon2");
    const weak = await argon2.hash("weakly-hashed-pw", {
      type: argon2.argon2id,
      memoryCost: 8192,
      timeCost: 1,
      parallelism: 1,
    });
    expect(needsRehash(weak)).toBe(true);
  });

  it("returns false rather than throwing on a malformed digest", () => {
    expect(needsRehash("not-a-hash")).toBe(false);
  });
});

describe("verifyAgainstDecoy", () => {
  // Without this, the response time of a login endpoint enumerates registered addresses.
  it("always resolves false", async () => {
    await expect(verifyAgainstDecoy("anything-at-all")).resolves.toBe(false);
  });

  it("spends real hashing work, comparable to verifying a genuine hash", async () => {
    const hash = await hashPassword("a-real-password-here");

    const realStart = performance.now();
    await verifyPassword(hash, "a-wrong-guess-here");
    const realMs = performance.now() - realStart;

    const decoyStart = performance.now();
    await verifyAgainstDecoy("a-wrong-guess-here");
    const decoyMs = performance.now() - decoyStart;

    // Deliberately a loose bound. This asserts the decoy path is doing KDF-scale work rather than
    // returning immediately; it is not a timing-attack measurement, which a unit test on shared
    // CI hardware cannot make meaningfully.
    expect(decoyMs).toBeGreaterThan(realMs / 10);
  });
});
