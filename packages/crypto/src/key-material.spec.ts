import { describe, expect, it } from "vitest";
import { SignJWT, jwtVerify } from "jose";
import {
  ENCRYPTION_ALG,
  ENCRYPTION_KEY_BYTES,
  SIGNING_ALG,
  generateEncryptionKey,
  generateSigningKey,
  importSigningKey,
  importVerificationKey,
  newKid,
  toJwks,
} from "./key-material";

describe("generateSigningKey", () => {
  it("produces ES256, not HS256", () => {
    expect(SIGNING_ALG).toBe("ES256");
  });

  it("returns a PKCS#8 private half and a publishable public half", async () => {
    const key = await generateSigningKey();
    expect(key.privatePkcs8).toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(key.publicJwk).toMatchObject({ kty: "EC", crv: "P-256", alg: "ES256", use: "sig" });
    expect(key.publicJwk.kid).toBe(key.kid);
  });

  // The whole point of moving off HS256: what a verifier receives must not let it mint.
  it("keeps the private scalar out of the public JWK", async () => {
    const key = await generateSigningKey();
    // 'd' is the EC private scalar. Its presence would make the published JWK a signing key.
    expect(key.publicJwk.d).toBeUndefined();
    expect(JSON.stringify(key.publicJwk)).not.toContain('"d"');
  });

  it("gives every key a distinct kid", async () => {
    const [a, b] = await Promise.all([generateSigningKey(), generateSigningKey()]);
    expect(a.kid).not.toBe(b.kid);
  });

  it("signs and verifies a JWS carrying the kid in its header", async () => {
    const key = await generateSigningKey();
    const priv = await importSigningKey(key.privatePkcs8);
    const pub = await importVerificationKey(key.publicJwk);

    const jws = await new SignJWT({ sub: "u" })
      .setProtectedHeader({ alg: SIGNING_ALG, kid: key.kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(priv);

    const { payload, protectedHeader } = await jwtVerify(jws, pub, { algorithms: [SIGNING_ALG] });
    expect(protectedHeader.kid).toBe(key.kid);
    expect(payload.sub).toBe("u");
  });

  // Rotation depends on this: a token signed by generation N must not verify under generation N+1.
  it("does not verify a token signed by a different key", async () => {
    const [a, b] = await Promise.all([generateSigningKey(), generateSigningKey()]);
    const jws = await new SignJWT({ sub: "u" })
      .setProtectedHeader({ alg: SIGNING_ALG, kid: a.kid })
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(await importSigningKey(a.privatePkcs8));

    await expect(
      jwtVerify(jws, await importVerificationKey(b.publicJwk), { algorithms: [SIGNING_ALG] }),
    ).rejects.toThrow();
  });
});

describe("generateEncryptionKey", () => {
  it("produces exactly the 256 bits A256KW requires", () => {
    const key = generateEncryptionKey();
    expect(key.algorithm).toBe(ENCRYPTION_ALG);
    expect(key.secret.byteLength).toBe(ENCRYPTION_KEY_BYTES);
  });

  it("does not repeat itself", () => {
    const a = Buffer.from(generateEncryptionKey().secret);
    const b = Buffer.from(generateEncryptionKey().secret);
    expect(a).not.toEqual(b);
  });
});

describe("newKid", () => {
  // A thumbprint-derived kid is stable across regenerations of the same key pair, which makes it
  // useless for distinguishing rotation generations. Random ids do not have that problem.
  it("is unique per call", () => {
    expect(new Set([newKid(), newKid(), newKid()]).size).toBe(3);
  });
});

describe("toJwks", () => {
  it("wraps public keys in a keys array", async () => {
    const key = await generateSigningKey();
    expect(toJwks([key.publicJwk])).toEqual({ keys: [key.publicJwk] });
  });

  // During a rotation overlap the previous key must remain published, or every token signed by it
  // becomes unverifiable the instant a new key goes active.
  it("carries more than one key, so a rotation overlap is representable", async () => {
    const [a, b] = await Promise.all([generateSigningKey(), generateSigningKey()]);
    expect(toJwks([a.publicJwk, b.publicJwk]).keys).toHaveLength(2);
  });

  it("refuses to import symmetric key material as a verification key", async () => {
    // An `oct` JWK would import to raw bytes, i.e. a shared secret that can both verify AND sign.
    // Accepting it would undo the entire reason for moving to ES256.
    const octJwk = { kty: "oct", k: Buffer.alloc(32, 1).toString("base64url"), alg: "ES256" };
    await expect(importVerificationKey(octJwk)).rejects.toThrow(/asymmetric public key/);
  });

  it("publishes nothing secret", async () => {
    const key = await generateSigningKey();
    const serialised = JSON.stringify(toJwks([key.publicJwk]));
    expect(serialised).not.toContain("PRIVATE KEY");
    expect(serialised).not.toContain('"d"');
  });
});
