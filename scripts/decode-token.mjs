#!/usr/bin/env node
/**
 * Decrypt and verify an access token, then print its claims as JSON.
 *
 * Access tokens are nested JWTs (signed, then encrypted), so unlike a plain JWS you cannot
 * paste one into a decoder and read it. That is the point, but it also means operators and
 * contributors need a supported way to inspect a token they legitimately hold the keys for.
 * This is that way, and it is also what the smoke test uses to assert on claims.
 *
 * It performs the FULL verification, both layers, exactly as the service does. It is not a
 * decoder: a token with a valid ciphertext but a bad inner signature exits non-zero.
 *
 * Usage:
 *   node scripts/decode-token.mjs <token>
 *   echo "$TOKEN" | node scripts/decode-token.mjs
 *
 * Reads JWT_SIGNING_KEY, JWT_ENCRYPTION_KEY, JWT_ISSUER and JWT_AUDIENCE from the
 * environment or from the repo-root .env.
 */
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compactDecrypt, jwtVerify } from "jose";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..");

// Minimal .env reader. Deliberately not a dependency: this is a dev tool and should keep
// working even from a partially installed tree.
function loadDotenv() {
  const file = path.join(REPO_ROOT, ".env");
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (process.env[key] === undefined) {
      process.env[key] = rawValue.replace(/^["']|["']$/g, "");
    }
  }
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

async function readToken() {
  const arg = process.argv[2];
  if (arg) return arg.trim();
  if (process.stdin.isTTY) fail("Usage: node scripts/decode-token.mjs <token>");
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8").trim();
}

loadDotenv();

const token = await readToken();
if (!token) fail("No token supplied.");

const signingKey = Buffer.from(process.env.JWT_SIGNING_KEY ?? "", "base64url");
const encryptionKey = Buffer.from(process.env.JWT_ENCRYPTION_KEY ?? "", "base64url");
if (signingKey.length !== 32 || encryptionKey.length !== 32) {
  fail("JWT_SIGNING_KEY and JWT_ENCRYPTION_KEY must each be a base64url 256-bit key.");
}

const segments = token.split(".").length;
if (segments !== 5) {
  fail(`Expected a 5-segment compact JWE, got ${segments} segments. Not a nested JWT.`);
}

// Layer 1: decrypt. Algorithms are allow-listed, and compression is refused.
let plaintext;
let outerHeader;
try {
  const decrypted = await compactDecrypt(token, new Uint8Array(encryptionKey), {
    keyManagementAlgorithms: ["A256KW"],
    contentEncryptionAlgorithms: ["A256GCM"],
    maxDecompressedLength: 0,
  });
  plaintext = decrypted.plaintext;
  outerHeader = decrypted.protectedHeader;
} catch (err) {
  fail(`Decryption failed: ${err.message}`);
}

if (outerHeader.cty !== "JWT") {
  fail(`Outer header cty is ${JSON.stringify(outerHeader.cty)}, expected "JWT" (RFC 7519 s5.2).`);
}

// Layer 2: verify the inner signature. Skipping this would accept an attacker-forged
// claims set from anyone holding the encryption key (RFC 8725 s2.3).
const innerJws = new TextDecoder().decode(plaintext);
let payload;
let innerHeader;
try {
  const verified = await jwtVerify(innerJws, new Uint8Array(signingKey), {
    algorithms: ["HS256"],
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE,
    typ: "crbk-at+jwt",
  });
  payload = verified.payload;
  innerHeader = verified.protectedHeader;
} catch (err) {
  fail(`Inner signature or claims invalid: ${err.message}`);
}

process.stdout.write(
  `${JSON.stringify(
    {
      outerHeader,
      innerHeader,
      innerSegments: innerJws.split(".").length,
      tokenBytes: token.length,
      claims: payload,
    },
    null,
    2,
  )}\n`,
);
