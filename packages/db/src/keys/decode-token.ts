/**
 * Decrypt and verify an access token, then print its claims.
 *
 * Access tokens are nested JWTs, so unlike a plain JWS you cannot paste one into a decoder and read
 * it. That is the point, but operators and contributors still need a supported way to inspect a
 * token they legitimately hold the keys for. This is that way, and the smoke test uses it to assert
 * on claims.
 *
 * It performs the FULL verification, both layers, exactly as the service does. It is not a decoder:
 * a token whose ciphertext is intact but whose inner signature is forged exits non-zero.
 *
 * Unlike the old symmetric version this has to reach the key registry, because the keys no longer
 * live in configuration. It reads the KEK from the environment, unwraps the relevant `config_keys`
 * rows, and resolves by the `kid` in the token headers, which is also a working demonstration of
 * what a verifier has to do.
 *
 * Usage:
 *   pnpm keys:decode <token>
 *   echo "$TOKEN" | pnpm keys:decode
 */
import { existsSync } from "node:fs";
import path from "node:path";
import { config as readDotenvFile } from "dotenv";
import {
  LocalKeyProvider,
  importVerificationKey,
  verifyNestedToken,
  type CryptoKey,
  type EncryptionKeyResolver,
  type JWK,
  type SigningKeyResolver,
} from "@compliance-kit/crypto";
import { ConnectionManager } from "../connection-manager";

/** Local development convenience only; skipped under NODE_ENV=production. */
function loadLocalDotenv(): void {
  if (process.env.NODE_ENV === "production") return;
  let dir = process.cwd();
  for (let level = 0; level < 5; level += 1) {
    const candidate = path.join(dir, ".env");
    if (existsSync(candidate)) {
      readDotenvFile({ path: candidate, quiet: true });
      return;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return;
    dir = parent;
  }
}

async function readToken(): Promise<string> {
  const arg = process.argv.slice(2).find((a) => !a.startsWith("--"));
  if (arg) return arg.trim();
  if (process.stdin.isTTY) throw new Error("Usage: pnpm keys:decode <token>");
  let text = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) text += chunk;
  return text.trim();
}

async function main(): Promise<void> {
  loadLocalDotenv();

  const token = await readToken();
  if (!token) throw new Error("No token supplied.");

  const segments = token.split(".").length;
  if (segments !== 5) {
    throw new Error(`Expected a 5-segment compact JWE, got ${segments}. Not a nested JWT.`);
  }

  const masterUrl = process.env.MASTER_DATABASE_URL;
  const kek = process.env.KEY_ENCRYPTION_KEY;
  if (!masterUrl || !kek) {
    throw new Error("MASTER_DATABASE_URL and KEY_ENCRYPTION_KEY must be set.");
  }

  const provider = new LocalKeyProvider(new Uint8Array(Buffer.from(kek, "base64url")));
  const cm = new ConnectionManager({ masterUrl, tenantClusterUrl: masterUrl });

  try {
    /**
     * Build resolvers over the registry, exactly as KeyRegistryService does, then hand them to the
     * SAME `verifyNestedToken` the service uses.
     *
     * Deliberately not a second decrypt-then-verify implementation. A parallel one could drift from
     * production and then this tool would report a token as good that the service rejects, or worse,
     * the reverse. Reusing the real codec means "the decoder accepted it" and "the service would
     * accept it" cannot disagree.
     *
     * The resolvers pre-load rather than query lazily, because the codec's resolvers are
     * synchronous by design: see the comment on TokenResolvers.
     */
    const rows = await cm.master.configKey.findMany({
      where: { state: { in: ["active", "retiring"] } },
    });

    const signing = new Map<string, CryptoKey>();
    const encryption = new Map<string, Uint8Array>();
    for (const row of rows) {
      if (!row.wrappedKey) continue;
      if (row.purpose === "token_signing") {
        if (row.publicJwk) {
          signing.set(row.kid, await importVerificationKey(row.publicJwk as JWK));
        }
      } else {
        encryption.set(
          row.kid,
          await provider.unwrap(new Uint8Array(row.wrappedKey), {
            purpose: row.purpose,
            kid: row.kid,
          }),
        );
      }
    }

    const signingResolver: SigningKeyResolver = (kid) => signing.get(kid);
    const encryptionResolver: EncryptionKeyResolver = (kid) => encryption.get(kid);

    // The headers come back from the verification itself, so everything reported below describes a
    // token that actually passed. There is no decode-without-verify path in this tool by design.
    const { claims, outerHeader, innerHeader } = await verifyNestedToken(
      token,
      { signing: signingResolver, encryption: encryptionResolver },
      {
        issuer: process.env.JWT_ISSUER ?? "",
        audience: process.env.JWT_AUDIENCE ?? "",
        ttlSeconds: Number(process.env.JWT_ACCESS_TTL_SECONDS ?? 900),
        clockToleranceSeconds: Number(process.env.JWT_CLOCK_TOLERANCE_SECONDS ?? 5),
      },
    );

    const activeSigningKid = rows.find(
      (r) => r.purpose === "token_signing" && r.state === "active",
    )?.kid;

    process.stdout.write(
      `${JSON.stringify(
        {
          outerHeader,
          innerHeader,
          activeSigningKid,
          // Whether the key that signed this token is still the active one. False is normal during a
          // rotation overlap and is the useful signal: it says this token predates the rotation and
          // will stop verifying when the retiring key's window closes.
          signedByActiveKey: innerHeader.kid === activeSigningKid,
          keysLoaded: { signing: signing.size, encryption: encryption.size },
          tokenBytes: token.length,
          claims,
        },
        null,
        2,
      )}\n`,
    );
  } finally {
    await cm.close();
  }
}

if (require.main === module) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
