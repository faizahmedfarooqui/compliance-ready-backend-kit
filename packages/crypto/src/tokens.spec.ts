import { describe, expect, it, vi } from "vitest";
import { CompactEncrypt, SignJWT, compactDecrypt, decodeProtectedHeader } from "jose";
import {
  TokenVerificationError,
  issueNestedToken,
  verifyNestedToken,
  type TokenMaterial,
  type TokenPolicy,
  type TokenResolvers,
} from "./tokens";
import {
  generateEncryptionKey,
  generateSigningKey,
  importSigningKey,
  importVerificationKey,
} from "./key-material";

/**
 * The negative paths matter more than the happy path. A nested JWT that round-trips is easy; one
 * that correctly REFUSES a token whose outer layer is perfect and whose inner signature is forged
 * is the whole reason for the design (RFC 8725 section 2.3). With kid-based rotation there is a
 * second class of attack to cover: a token that names a key of the attacker's choosing.
 */

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

/** A key set plus the resolvers that can find it, as the registry would supply them. */
async function keySet() {
  const signing = await generateSigningKey();
  const encryption = generateEncryptionKey();
  const privateKey = await importSigningKey(signing.privatePkcs8);
  const publicKey = await importVerificationKey(signing.publicJwk);

  const material: TokenMaterial = {
    signing: { kid: signing.kid, key: privateKey },
    encryption: { kid: encryption.kid, key: encryption.secret },
  };

  const resolvers: TokenResolvers = {
    signing: (kid) => (kid === signing.kid ? publicKey : undefined),
    encryption: (kid) => (kid === encryption.kid ? encryption.secret : undefined),
  };

  return { signing, encryption, material, resolvers, publicKey };
}

describe("issueNestedToken", () => {
  it("produces a 5-segment JWE whose plaintext is a 3-segment JWS", async () => {
    const { material, encryption } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    expect(token.split(".")).toHaveLength(5);

    const { plaintext } = await compactDecrypt(token, encryption.secret);
    expect(new TextDecoder().decode(plaintext).split(".")).toHaveLength(3);
  });

  it("marks the outer header as a nested JWT with cty=JWT (RFC 7519 s5.2)", async () => {
    const { material } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    expect(decodeProtectedHeader(token)).toMatchObject({
      alg: "A256KW",
      enc: "A256GCM",
      cty: "JWT",
    });
  });

  it("signs with ES256, not HS256", async () => {
    const { material, encryption } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const { plaintext } = await compactDecrypt(token, encryption.secret);
    expect(decodeProtectedHeader(new TextDecoder().decode(plaintext))).toMatchObject({
      alg: "ES256",
      typ: "crbk-at+jwt",
    });
  });

  // Without a kid on each layer a verifier cannot tell which key signed a token, so a rotation
  // overlap is impossible: it would have to try every key, which is both slow and a way to accept
  // a token under a key you meant to retire.
  it("names the key in both layers with a kid", async () => {
    const { material, encryption, signing } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);

    expect(decodeProtectedHeader(token).kid).toBe(encryption.kid);
    const { plaintext } = await compactDecrypt(token, encryption.secret);
    expect(decodeProtectedHeader(new TextDecoder().decode(plaintext)).kid).toBe(signing.kid);
  });

  it("leaks no claim into the outer header, which is not encrypted", async () => {
    const { material } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const header = decodeProtectedHeader(token) as Record<string, unknown>;
    for (const claim of ["sub", "tid", "roles", "permissions", "iss", "aud", "exp", "iat"]) {
      expect(header[claim]).toBeUndefined();
    }
  });

  it("round-trips the claims", async () => {
    const { material, resolvers } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const { claims } = await verifyNestedToken(token, resolvers, POLICY);
    expect(claims).toMatchObject(CLAIMS);
    expect(claims.iss).toBe(POLICY.issuer);
    expect(claims.aud).toBe(POLICY.audience);
  });

  /**
   * The headers are returned only alongside verified claims, never on their own. That is the whole
   * point of the shape: an operator can see which key verified a token, but there is no API here that
   * hands back a header for a token that failed, so nothing can be read off an unverified token and
   * mistaken for trustworthy (RFC 8725 section 2.3).
   */
  it("reports the two headers it actually validated", async () => {
    const { material, resolvers } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const { innerHeader, outerHeader } = await verifyNestedToken(token, resolvers, POLICY);

    // The inner kid is what a third party looks up in the published JWKS.
    expect(innerHeader.kid).toBe(material.signing.kid);
    expect(innerHeader.alg).toBe("ES256");
    expect(outerHeader.kid).toBe(material.encryption.kid);
    expect(outerHeader.alg).toBe("A256KW");
    expect(outerHeader.enc).toBe("A256GCM");
    expect(outerHeader.cty).toBe("JWT");
  });
});

describe("material validation", () => {
  it("refuses an encryption key that is not exactly 32 bytes", async () => {
    const { material } = await keySet();
    const bad = { ...material, encryption: { kid: "e1", key: new Uint8Array(16) } };
    await expect(issueNestedToken(CLAIMS, bad, POLICY)).rejects.toThrow(/exactly 32 bytes/);
  });

  it("refuses material with a missing kid", async () => {
    const { material } = await keySet();
    const bad = { ...material, signing: { ...material.signing, kid: "" } };
    await expect(issueNestedToken(CLAIMS, bad, POLICY)).rejects.toThrow(/must carry a kid/);
  });

  it("refuses the same kid for both keys, which would make a rotation audit ambiguous", async () => {
    const { material } = await keySet();
    const bad = {
      signing: { ...material.signing, kid: "shared" },
      encryption: { ...material.encryption, kid: "shared" },
    };
    await expect(issueNestedToken(CLAIMS, bad, POLICY)).rejects.toThrow(/distinct kids/);
  });
});

describe("kid resolution", () => {
  // The attack kid-based selection invites: name a key the attacker controls, or one that should no
  // longer be trusted, and see whether the verifier follows.
  it("rejects a token naming an unknown encryption kid", async () => {
    const { material, resolvers } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const noKeys: TokenResolvers = { ...resolvers, encryption: () => undefined };
    await expect(verifyNestedToken(token, noKeys, POLICY)).rejects.toThrow(/decryption failed/);
  });

  it("rejects a token naming an unknown signing kid, even though it decrypts", async () => {
    const { material, resolvers } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const noSigning: TokenResolvers = { ...resolvers, signing: () => undefined };
    await expect(verifyNestedToken(token, noSigning, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  // A revoked key is modelled as a resolver that stops returning it. This is the test that proves
  // revocation actually takes effect rather than being a database state nobody consults.
  it("rejects a token whose signing key has been revoked mid-life", async () => {
    const { material, resolvers, signing, publicKey } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);

    await expect(verifyNestedToken(token, resolvers, POLICY)).resolves.toBeDefined();

    const revoked: TokenResolvers = {
      ...resolvers,
      signing: (kid) => (kid === signing.kid ? undefined : publicKey),
    };
    await expect(verifyNestedToken(token, revoked, POLICY)).rejects.toThrow(TokenVerificationError);
  });

  // An absent kid must not fall back to "whatever is active". A fallback would let a token minted
  // under a retired or revoked key be accepted simply by stripping the header.
  it("rejects a token with no kid rather than falling back to an active key", async () => {
    const { material, resolvers, encryption } = await keySet();
    const jws = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt" })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(material.signing.key);

    const noKid = await new CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: "A256KW", enc: "A256GCM", cty: "JWT" })
      .encrypt(encryption.secret);

    await expect(verifyNestedToken(noKid, resolvers, POLICY)).rejects.toThrow(/decryption failed/);
  });

  /**
   * The reason the resolvers are synchronous. jose calls them before anything is verified, so the
   * kid is attacker input; if resolution could await, a forged kid would drive a database query or a
   * KMS unwrap per request. Asserting the resolver returns a value rather than a thenable is how
   * that property stays true after someone "just makes it async" to add a cache refresh.
   */
  it("calls resolvers synchronously, so a forged kid cannot reach a database", async () => {
    const { material, resolvers } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);

    const signing = vi.fn(resolvers.signing);
    const encryption = vi.fn(resolvers.encryption);
    await verifyNestedToken(token, { signing, encryption }, POLICY);

    for (const spy of [signing, encryption]) {
      expect(spy).toHaveBeenCalled();
      for (const result of spy.mock.results) {
        expect(result.value).not.toHaveProperty("then");
      }
    }
  });
});

describe("verifyNestedToken rejects", () => {
  it("a valid JWE wrapping a FORGED inner signature (RFC 8725 s2.3)", async () => {
    // The outer layer is flawless: correct encryption key, correct algorithms, correct cty, correct
    // kid. Only the inner signature is wrong, because it was made by a different key pair. An
    // implementation that decrypted and trusted the result would accept this and grant tenant-admin.
    const { material, resolvers, encryption, signing } = await keySet();
    const attacker = await generateSigningKey();

    const forgedJws = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt", kid: signing.kid })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(await importSigningKey(attacker.privatePkcs8));

    const forged = await new CompactEncrypt(new TextEncoder().encode(forgedJws))
      .setProtectedHeader({
        alg: "A256KW",
        enc: "A256GCM",
        cty: "JWT",
        kid: material.encryption.kid,
      })
      .encrypt(encryption.secret);

    // Prove the outer layer really is valid, so the rejection can only come from the signature.
    await expect(compactDecrypt(forged, encryption.secret)).resolves.toBeDefined();

    await expect(verifyNestedToken(forged, resolvers, POLICY)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  it("a bare JWS that was never encrypted", async () => {
    const { material, resolvers, signing } = await keySet();
    const bare = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt", kid: signing.kid })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(material.signing.key);

    expect(bare.split(".")).toHaveLength(3);
    await expect(verifyNestedToken(bare, resolvers, POLICY)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  /**
   * The INNER header's kid, checked separately from the outer one.
   *
   * Both layers need this and for different reasons. The outer kid selects a decryption key; the
   * inner kid selects a verification key. Falling back to "the active signing key" when the inner kid
   * is missing would resurrect every key ever retired or revoked: an attacker holding a token signed
   * by a compromised key strips the inner kid, and the token gets checked against whichever key is
   * current instead of being refused. That is a downgrade to HS256-era behaviour, where there was
   * only one key and nothing to name.
   *
   * The outer layer here is deliberately perfect, so the rejection can only come from the inner kid.
   */
  it("a nested token whose INNER header omits kid, rather than falling back to the active key", async () => {
    const { resolvers, encryption, material } = await keySet();

    const noInnerKid = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt" }) // no kid
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(material.signing.key);

    expect(decodeProtectedHeader(noInnerKid).kid).toBeUndefined();

    const token = await new CompactEncrypt(new TextEncoder().encode(noInnerKid))
      .setProtectedHeader({
        alg: "A256KW",
        enc: "A256GCM",
        cty: "JWT",
        kid: encryption.kid,
      })
      .encrypt(encryption.secret);

    // The outer layer is valid, so only the missing inner kid can be the cause.
    await expect(compactDecrypt(token, encryption.secret)).resolves.toBeDefined();
    await expect(verifyNestedToken(token, resolvers, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  // The signature is genuine and the token well formed; the key it names simply is not one this
  // deployment will accept. Distinct from the revoked-mid-life case: there the kid was known and
  // withdrawn, here it was never ours.
  it("a nested token whose INNER header names a signing key we do not hold", async () => {
    const { resolvers, encryption } = await keySet();
    const stranger = await generateSigningKey();

    const foreignJws = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt", kid: stranger.kid })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(await importSigningKey(stranger.privatePkcs8));

    const token = await new CompactEncrypt(new TextEncoder().encode(foreignJws))
      .setProtectedHeader({ alg: "A256KW", enc: "A256GCM", cty: "JWT", kid: encryption.kid })
      .encrypt(encryption.secret);

    await expect(verifyNestedToken(token, resolvers, POLICY)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  // jose neither sets nor checks cty, so without an explicit check this would pass.
  it("a nested token whose outer header omits cty", async () => {
    const { material, resolvers, encryption } = await keySet();
    const jws = await new SignJWT(CLAIMS)
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt", kid: material.signing.kid })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(material.signing.key);

    const noCty = await new CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: "A256KW", enc: "A256GCM", kid: encryption.kid })
      .encrypt(encryption.secret);

    await expect(verifyNestedToken(noCty, resolvers, POLICY)).rejects.toThrow(/not a nested JWT/);
  });

  it("a token whose ciphertext has been tampered with", async () => {
    const { material, resolvers } = await keySet();
    const token = await issueNestedToken(CLAIMS, material, POLICY);
    const parts = token.split(".");
    // Flip a byte of the ciphertext, not a base64url character: a segment's trailing character
    // carries only a couple of significant bits and can re-encode to identical bytes.
    const buf = Buffer.from(parts[3], "base64url");
    buf[0] ^= 0xff;
    parts[3] = buf.toString("base64url");

    await expect(verifyNestedToken(parts.join("."), resolvers, POLICY)).rejects.toThrow(
      /decryption failed/,
    );
  });

  it.each([
    ["an expired token", { expiresIn: "-60s" }],
    ["a different issuer", { issuer: "someone-else" }],
    ["a different audience", { audience: "another-api" }],
    ["the wrong typ", { typ: "at+jwt" }],
  ])("%s", async (_label, override: Record<string, string>) => {
    const { material, resolvers, encryption } = await keySet();
    const jws = await new SignJWT(CLAIMS)
      .setProtectedHeader({
        alg: "ES256",
        typ: override.typ ?? "crbk-at+jwt",
        kid: material.signing.kid,
      })
      .setIssuer(override.issuer ?? POLICY.issuer)
      .setAudience(override.audience ?? POLICY.audience)
      .setIssuedAt()
      .setExpirationTime(override.expiresIn ?? "900s")
      .sign(material.signing.key);

    const token = await new CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: "A256KW", enc: "A256GCM", cty: "JWT", kid: encryption.kid })
      .encrypt(encryption.secret);

    await expect(verifyNestedToken(token, resolvers, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  it("a token missing a required claim", async () => {
    const { material, resolvers, encryption } = await keySet();
    const jws = await new SignJWT({ sub: CLAIMS.sub, tid: CLAIMS.tid, roles: CLAIMS.roles })
      .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt", kid: material.signing.kid })
      .setIssuer(POLICY.issuer)
      .setAudience(POLICY.audience)
      .setIssuedAt()
      .setExpirationTime("900s")
      .sign(material.signing.key);

    const token = await new CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: "A256KW", enc: "A256GCM", cty: "JWT", kid: encryption.kid })
      .encrypt(encryption.secret);

    await expect(verifyNestedToken(token, resolvers, POLICY)).rejects.toThrow(
      /signature or claims invalid/,
    );
  });

  it("garbage", async () => {
    const { resolvers } = await keySet();
    await expect(verifyNestedToken("not-a-token", resolvers, POLICY)).rejects.toThrow(
      TokenVerificationError,
    );
  });

  // Every failure collapses to one of two messages. Saying which check failed tells an attacker
  // which part of a forged token to fix next.
  it("without disclosing which claim check failed", async () => {
    const { material, resolvers, encryption } = await keySet();

    const build = async (o: Record<string, string>) => {
      const jws = await new SignJWT(CLAIMS)
        .setProtectedHeader({ alg: "ES256", typ: "crbk-at+jwt", kid: material.signing.kid })
        .setIssuer(o.issuer ?? POLICY.issuer)
        .setAudience(o.audience ?? POLICY.audience)
        .setIssuedAt()
        .setExpirationTime(o.expiresIn ?? "900s")
        .sign(material.signing.key);
      return new CompactEncrypt(new TextEncoder().encode(jws))
        .setProtectedHeader({ alg: "A256KW", enc: "A256GCM", cty: "JWT", kid: encryption.kid })
        .encrypt(encryption.secret);
    };

    const messages = await Promise.all(
      [await build({ expiresIn: "-60s" }), await build({ audience: "another-api" })].map((t) =>
        verifyNestedToken(t, resolvers, POLICY).then(
          () => "unexpectedly accepted",
          (err: unknown) => (err as Error).message,
        ),
      ),
    );
    expect(messages[0]).toBe(messages[1]);
  });
});

describe("rotation overlap", () => {
  // The property that makes rotation graceful: a token signed by the previous key keeps verifying
  // while that key is `retiring`. Without it, activating a new key invalidates every live token.
  it("verifies a token signed by a retiring key while the resolver still returns it", async () => {
    const previous = await keySet();
    const current = await keySet();

    const tokenFromPrevious = await issueNestedToken(CLAIMS, previous.material, POLICY);

    // A registry mid-rotation: the new key is active, the old one is retiring but still resolvable.
    const overlapping: TokenResolvers = {
      signing: (kid) =>
        kid === current.signing.kid
          ? current.publicKey
          : kid === previous.signing.kid
            ? previous.publicKey
            : undefined,
      encryption: (kid) =>
        kid === current.encryption.kid
          ? current.encryption.secret
          : kid === previous.encryption.kid
            ? previous.encryption.secret
            : undefined,
    };

    await expect(verifyNestedToken(tokenFromPrevious, overlapping, POLICY)).resolves.toMatchObject({
      claims: CLAIMS,
      // Still names the OLD key, which is what makes the overlap observable rather than just working.
      innerHeader: { kid: previous.signing.kid },
    });

    const tokenFromCurrent = await issueNestedToken(CLAIMS, current.material, POLICY);
    await expect(verifyNestedToken(tokenFromCurrent, overlapping, POLICY)).resolves.toMatchObject({
      claims: CLAIMS,
      innerHeader: { kid: current.signing.kid },
    });
  });

  it("stops verifying once the retiring key drops out of the resolver", async () => {
    const previous = await keySet();
    const current = await keySet();
    const token = await issueNestedToken(CLAIMS, previous.material, POLICY);

    // Overlap over: only the current key resolves.
    await expect(verifyNestedToken(token, current.resolvers, POLICY)).rejects.toThrow(
      TokenVerificationError,
    );
  });
});
