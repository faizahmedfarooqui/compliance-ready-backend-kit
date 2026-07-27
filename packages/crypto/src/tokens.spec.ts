import { describe, expect, it } from "vitest";
import { CompactEncrypt, SignJWT, compactDecrypt, decodeProtectedHeader } from "jose";
import {
  TOKEN_KEY_BYTES,
  TokenVerificationError,
  issueNestedToken,
  verifyNestedToken,
  type TokenKeys,
  type TokenPolicy,
} from "./tokens";

/**
 * The negative paths matter more than the happy path here. A nested JWT that round-trips is easy;
 * one that correctly REFUSES a token whose outer layer is perfect and whose inner signature is
 * forged is the whole reason for the design (RFC 8725 s2.3).
 */

const KEYS: TokenKeys = {
  signingKey: new Uint8Array(TOKEN_KEY_BYTES).fill(1),
  encryptionKey: new Uint8Array(TOKEN_KEY_BYTES).fill(2),
};

const POLICY: TokenPolicy = {
  issuer: "test-issuer",
  audience: "test-audience",
  ttlSeconds: 900,
};

const CLAIMS = {
  sub: "11111111-1111-4111-8111-111111111111",
  tid: "22222222-2222-4222-8222-222222222222",
  roles: ["tenant-admin"],
  permissions: ["users:read"],
};

/** Build a JWE by hand so individual layers can be made wrong on purpose. */
async function handRolledToken(options: {
  signingKey?: Uint8Array;
  encryptionKey?: Uint8Array;
  cty?: string | undefined;
  issuer?: string;
  audience?: string;
  expiresIn?: string;
  typ?: string;
  claims?: Record<string, unknown>;
}): Promise<string> {
  const jws = await new SignJWT(options.claims ?? CLAIMS)
    .setProtectedHeader({ alg: "HS256", typ: options.typ ?? "crbk-at+jwt" })
    .setIssuer(options.issuer ?? POLICY.issuer)
    .setAudience(options.audience ?? POLICY.audience)
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? "900s")
    .sign(options.signingKey ?? KEYS.signingKey);

  const header: Record<string, unknown> = { alg: "A256KW", enc: "A256GCM" };
  if (options.cty !== undefined) header.cty = options.cty;

  return new CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader(header as Parameters<CompactEncrypt["setProtectedHeader"]>[0])
    .encrypt(options.encryptionKey ?? KEYS.encryptionKey);
}

describe("issueNestedToken", () => {
  it("produces a 5-segment JWE whose plaintext is a 3-segment JWS", async () => {
    const token = await issueNestedToken(CLAIMS, KEYS, POLICY);
    expect(token.split(".")).toHaveLength(5);

    const { plaintext } = await compactDecrypt(token, KEYS.encryptionKey);
    expect(new TextDecoder().decode(plaintext).split(".")).toHaveLength(3);
  });

  it("marks the outer header as a nested JWT with cty=JWT (RFC 7519 s5.2)", async () => {
    const token = await issueNestedToken(CLAIMS, KEYS, POLICY);
    expect(decodeProtectedHeader(token)).toMatchObject({
      alg: "A256KW",
      enc: "A256GCM",
      cty: "JWT",
    });
  });

  it("types the inner JWS as crbk-at+jwt, not the RFC 9068 at+jwt it does not conform to", async () => {
    const token = await issueNestedToken(CLAIMS, KEYS, POLICY);
    const { plaintext } = await compactDecrypt(token, KEYS.encryptionKey);
    const inner = new TextDecoder().decode(plaintext);
    expect(decodeProtectedHeader(inner)).toMatchObject({ alg: "HS256", typ: "crbk-at+jwt" });
  });

  it("leaks no claim into the outer header, which is not encrypted", async () => {
    const token = await issueNestedToken(CLAIMS, KEYS, POLICY);
    const header = decodeProtectedHeader(token) as Record<string, unknown>;
    for (const claim of ["sub", "tid", "roles", "permissions", "iss", "aud", "exp", "iat"]) {
      expect(header[claim]).toBeUndefined();
    }
  });

  it("round-trips the claims", async () => {
    const token = await issueNestedToken(CLAIMS, KEYS, POLICY);
    const payload = await verifyNestedToken(token, KEYS, POLICY);
    expect(payload).toMatchObject(CLAIMS);
    expect(payload.iss).toBe(POLICY.issuer);
    expect(payload.aud).toBe(POLICY.audience);
  });
});

describe("key handling", () => {
  it("refuses a signing key that is not exactly 32 bytes", async () => {
    const keys = { ...KEYS, signingKey: new Uint8Array(16).fill(1) };
    await expect(issueNestedToken(CLAIMS, keys, POLICY)).rejects.toThrow(/exactly 32 bytes/);
  });

  it("refuses an encryption key that is not exactly 32 bytes", async () => {
    const keys = { ...KEYS, encryptionKey: new Uint8Array(64).fill(2) };
    await expect(issueNestedToken(CLAIMS, keys, POLICY)).rejects.toThrow(/exactly 32 bytes/);
  });

  // Reusing one secret couples two independent properties: recovering it would let an attacker
  // both forge tokens and decrypt them. jose will not stop you, so this must.
  it("refuses to use the same key for signing and encryption", async () => {
    const shared = new Uint8Array(TOKEN_KEY_BYTES).fill(7);
    const keys = { signingKey: shared, encryptionKey: shared };
    await expect(issueNestedToken(CLAIMS, keys, POLICY)).rejects.toThrow(/different keys/);
  });
});

describe("verifyNestedToken rejects", () => {
  it("a valid JWE wrapping a FORGED inner signature (RFC 8725 s2.3)", async () => {
    // The outer layer is flawless: correct encryption key, correct algorithms, correct cty. Only
    // the inner signature is wrong. An implementation that decrypted and trusted the result would
    // accept this and hand the caller tenant-admin.
    const forged = await handRolledToken({
      signingKey: new Uint8Array(TOKEN_KEY_BYTES).fill(9),
      cty: "JWT",
    });

    // Prove the outer layer really is valid, so the rejection can only come from the signature.
    await expect(compactDecrypt(forged, KEYS.encryptionKey)).resolves.toBeDefined();

    await expect(verifyNestedToken(forged, KEYS, POLICY)).rejects.toThrow(TokenVerificationError);
  });

  it("a bare JWS that was never encrypted", async () => {
    const bare = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "HS256", typ: "crbk-at+jwt" })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(KEYS.signingKey);

    expect(bare.split(".")).toHaveLength(3);
    await expect(verifyNestedToken(bare, KEYS, POLICY)).rejects.toThrow(TokenVerificationError);
  });

  // jose neither sets nor checks cty, so if the codec did not check it explicitly this would pass.
  it("a nested token whose outer header omits cty", async () => {
    const noCty = await handRolledToken({ cty: undefined });
    await expect(verifyNestedToken(noCty, KEYS, POLICY)).rejects.toThrow(/not a nested JWT/);
  });

  it("a nested token whose outer cty is something else", async () => {
    const wrongCty = await handRolledToken({ cty: "JSON" });
    await expect(verifyNestedToken(wrongCty, KEYS, POLICY)).rejects.toThrow(/not a nested JWT/);
  });

  it("a token encrypted with the wrong key", async () => {
    const wrongKey = await handRolledToken({
      encryptionKey: new Uint8Array(TOKEN_KEY_BYTES).fill(8),
      cty: "JWT",
    });
    await expect(verifyNestedToken(wrongKey, KEYS, POLICY)).rejects.toThrow(/decryption failed/);
  });

  it("a token whose ciphertext has been tampered with", async () => {
    const token = await issueNestedToken(CLAIMS, KEYS, POLICY);
    const parts = token.split(".");
    // Flip a byte of the ciphertext, not a base64url character: the trailing character of a
    // segment carries only a couple of significant bits and can re-encode to identical bytes.
    const buf = Buffer.from(parts[3], "base64url");
    buf[0] ^= 0xff;
    parts[3] = buf.toString("base64url");

    await expect(verifyNestedToken(parts.join("."), KEYS, POLICY)).rejects.toThrow(
      /decryption failed/,
    );
  });

  it("an expired token", async () => {
    const expired = await handRolledToken({ cty: "JWT", expiresIn: "-60s" });
    await expect(verifyNestedToken(expired, KEYS, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  it("a token minted by a different issuer", async () => {
    const other = await handRolledToken({ cty: "JWT", issuer: "someone-else" });
    await expect(verifyNestedToken(other, KEYS, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  // Stops a token minted for another service that happens to share these keys.
  it("a token for a different audience", async () => {
    const other = await handRolledToken({ cty: "JWT", audience: "another-api" });
    await expect(verifyNestedToken(other, KEYS, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  it("a token carrying the wrong typ", async () => {
    const other = await handRolledToken({ cty: "JWT", typ: "at+jwt" });
    await expect(verifyNestedToken(other, KEYS, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  it("a token missing a required claim", async () => {
    const incomplete = await handRolledToken({
      cty: "JWT",
      claims: { sub: CLAIMS.sub, tid: CLAIMS.tid, roles: CLAIMS.roles },
    });
    await expect(verifyNestedToken(incomplete, KEYS, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  it("garbage", async () => {
    await expect(verifyNestedToken("not-a-token", KEYS, POLICY)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  // Every failure collapses to one message. Saying which check failed tells an attacker which
  // part of a forged token to fix next.
  it("without disclosing which check failed beyond decrypt-vs-verify", async () => {
    const expired = await handRolledToken({ cty: "JWT", expiresIn: "-60s" });
    const wrongAud = await handRolledToken({ cty: "JWT", audience: "another-api" });

    const messages = await Promise.all(
      [expired, wrongAud].map((t) =>
        verifyNestedToken(t, KEYS, POLICY).then(
          () => "unexpectedly accepted",
          (err: unknown) => (err as Error).message,
        ),
      ),
    );
    expect(messages[0]).toBe(messages[1]);
  });
});
