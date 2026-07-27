#!/usr/bin/env bash
#
# End-to-end smoke test against a running auth-service.
#
# Proves the paths that matter, in order:
#   1-2.  a tenant can be provisioned with its own database and RBAC catalogue, and a
#         duplicate slug is refused
#   3-4.  provisioning creates NO users, and the seed file grants the first administrator
#         (idempotently)
#   5-6.  the access token is a nested JWT whose claims are unreadable without the key, and
#         whose verified claims carry tenant id, user id, roles and permissions
#   7-9.  the seeded admin can read users (RBAC allows) and a freshly registered user cannot
#         (RBAC denies)
#   10.   wrong password and unknown user fail identically
#   11.   two tenants cannot see each other's users            (isolation holds)
#   12.   a token minted for one tenant is refused by another  (authorization holds)
#   13.   forged, unencrypted and tampered tokens are all refused
#   14.   an unknown tenant and a missing header are rejected
#   15.   every response follows the contract: RFC 9457 problem details for errors,
#         { success, data, meta } for success
#
# Usage:
#   docker compose up -d
#   pnpm db:migrate
#   pnpm build
#   pnpm start:auth &
#   ./scripts/smoke-test.sh
#
# Requires: curl, jq, node. Override the target with BASE_URL.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://localhost:3011/api}"
SEED_CLI="$REPO_ROOT/packages/db/dist/seed/seed-tenant-admin.js"
# A unique suffix keeps repeat runs from colliding on the tenant slug unique index.
RUN_ID="${RUN_ID:-$(date +%s)}"
ADMIN_PASSWORD="smoke-admin-pw-0123456789"
USER_PASSWORD="smoke-user-pw-0123456789"

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
FAILURES=0

if [ ! -f "$SEED_CLI" ]; then
  printf '\033[31mMissing %s\033[0m\nRun `pnpm build` first.\n' "$SEED_CLI"
  exit 1
fi

# Echo the HTTP status on the last line so callers can assert on it.
req() {
  local method="$1" path="$2" body="${3:-}" ; shift 3 || shift 2
  if [ -n "$body" ]; then
    curl -sS -o /tmp/smoke-body -w '%{http_code}' -X "$method" "$BASE_URL$path" \
      -H 'content-type: application/json' "$@" -d "$body"
  else
    curl -sS -o /tmp/smoke-body -w '%{http_code}' -X "$method" "$BASE_URL$path" "$@"
  fi
}

expect_status() {
  local want="$1" got="$2" label="$3"
  if [ "$got" = "$want" ]; then
    pass "$label (HTTP $got)"
  else
    fail "$label: expected HTTP $want, got $got -- $(cat /tmp/smoke-body)"
  fi
}

# Fully decrypt AND verify a token, then emit its claims. Access tokens are nested JWTs, so
# there is no payload to read without the keys; this shells out to the same two-layer
# verification the service performs.
token_claims() {
  node "$REPO_ROOT/scripts/decode-token.mjs" "$1" | jq '.claims'
}

# The forged-token fixtures below need the real keys. Take them from the environment first and
# fall back to .env, which is the same precedence the service itself uses.
#
# Do NOT read .env unconditionally: CI has no .env at all (the keys come from the workflow's
# `env:` block), so `KEY=$(grep ... .env)` aborts the whole script under `set -e`. That is
# exactly how this failed on its first run against GitHub Actions.
key_from_env_or_file() {
  local name="$1"
  if [ -n "${!name:-}" ]; then
    printf '%s' "${!name}"
    return 0
  fi
  if [ -f "$REPO_ROOT/.env" ]; then
    grep -h "^$name=" "$REPO_ROOT/.env" | head -1 | cut -d= -f2- || true
  fi
}

seed_admin() {
  local tenant="$1" email="$2"
  SEED_ADMIN_PASSWORD="$ADMIN_PASSWORD" node "$SEED_CLI" --tenant "$tenant" --email "$email"
}

login() {
  local tenant="$1" email="$2" password="$3"
  req POST /auth/login "{\"email\":\"$email\",\"password\":\"$password\"}" \
    -H "x-tenant-id: $tenant" >/dev/null
  jq -r '.data.accessToken' /tmp/smoke-body
}

step "0. Which server am I talking to?"
# A stale process holding the port answers every request happily, so a suite pointed at it
# reports a pass for code that is not running. This nearly happened during development: a
# `nest start --watch` left over from an earlier test kept :3011, the freshly built server
# failed to bind with EADDRINUSE, and 64 checks passed against the wrong process.
#
# Uptime is the tell. Override SMOKE_MAX_UPTIME if you are deliberately testing a long-lived
# dev server; set it to 0 to skip the check.
SMOKE_MAX_UPTIME="${SMOKE_MAX_UPTIME:-1800}"
if ! curl -sS -o /tmp/smoke-health "$BASE_URL/health" 2>/dev/null; then
  printf '\033[31mNo server on %s\033[0m\nStart it with `pnpm start:auth`.\n' "$BASE_URL"
  exit 1
fi
served_version=$(jq -r '.data.version' /tmp/smoke-health 2>/dev/null)
served_uptime=$(jq -r '.data.uptimeSeconds' /tmp/smoke-health 2>/dev/null)
local_version=$(jq -r '.version' "$REPO_ROOT/services/auth/package.json")
printf '  serving %s v%s, up %ss (started %s)\n' \
  "$(jq -r '.data.service' /tmp/smoke-health)" "$served_version" "$served_uptime" \
  "$(jq -r '.data.startedAt' /tmp/smoke-health)"

[ "$served_version" = "$local_version" ] \
  && pass "served version matches services/auth/package.json ($local_version)" \
  || fail "version mismatch: server says $served_version, repo says $local_version"

if [ "$SMOKE_MAX_UPTIME" -gt 0 ] 2>/dev/null; then
  if [ "$served_uptime" -le "$SMOKE_MAX_UPTIME" ] 2>/dev/null; then
    pass "server was started recently (${served_uptime}s <= ${SMOKE_MAX_UPTIME}s), so it is the build under test"
  else
    fail "server has been up ${served_uptime}s, longer than SMOKE_MAX_UPTIME=${SMOKE_MAX_UPTIME}s. It may predate your build; restart with ./scripts/stop-auth.sh && pnpm start:auth"
  fi
fi

# One listener only. Two would mean the port is contested and which one answers is a coin toss.
if command -v lsof >/dev/null 2>&1; then
  listeners=$(lsof -tnP -iTCP:"${PORT:-3011}" -sTCP:LISTEN 2>/dev/null | wc -l | tr -d ' ')
  [ "$listeners" = "1" ] \
    && pass "exactly one process is listening on :${PORT:-3011}" \
    || fail "$listeners processes listening on :${PORT:-3011}; run ./scripts/stop-auth.sh"
fi

TENANT_A="smoke-a-$RUN_ID"
TENANT_B="smoke-b-$RUN_ID"
ADMIN_A="admin@$TENANT_A.example"
ADMIN_B="admin@$TENANT_B.example"

step "1. Provision two tenants (each gets its own database)"
status=$(req POST /tenants "{\"slug\":\"$TENANT_A\",\"name\":\"Smoke A\"}")
expect_status 201 "$status" "POST /tenants ($TENANT_A)"
TENANT_A_ID=$(jq -r '.data.id' /tmp/smoke-body)
[ "$(jq -r '.data.status' /tmp/smoke-body)" = "active" ] \
  && pass "tenant marked active after provisioning" \
  || fail "tenant status is not active: $(cat /tmp/smoke-body)"

status=$(req POST /tenants "{\"slug\":\"$TENANT_B\",\"name\":\"Smoke B\"}")
expect_status 201 "$status" "POST /tenants ($TENANT_B)"

step "2. Duplicate slug is rejected"
status=$(req POST /tenants "{\"slug\":\"$TENANT_A\",\"name\":\"Dup\"}")
expect_status 409 "$status" "POST /tenants with an existing slug"

step "3. Provisioning creates no users, so nobody can log in yet"
status=$(req POST /auth/login "{\"email\":\"$ADMIN_A\",\"password\":\"$ADMIN_PASSWORD\"}" \
  -H "x-tenant-id: $TENANT_A")
expect_status 401 "$status" "login before the admin is seeded"

step "4. Seed the first administrator from the seed file"
if seed_admin "$TENANT_A" "$ADMIN_A" | grep -q "Created"; then
  pass "seed file created the admin and granted tenant-admin"
else
  fail "seed file did not report creating the admin"
fi
seed_admin "$TENANT_B" "$ADMIN_B" >/dev/null

# Re-running must be safe: it should find the existing user, not duplicate or re-hash.
if seed_admin "$TENANT_A" "$ADMIN_A" | grep -q "Found existing"; then
  pass "seed file is idempotent on a second run"
else
  fail "seed file is not idempotent"
fi

step "5. The token is a nested JWT: signed, then encrypted"
ADMIN_TOKEN=$(login "$TENANT_A" "$ADMIN_A" "$ADMIN_PASSWORD")
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] \
  && pass "admin login returned a token" \
  || fail "admin login did not return a token: $(cat /tmp/smoke-body)"

[ "$(printf '%s' "$ADMIN_TOKEN" | awk -F. '{print NF}')" = "5" ] \
  && pass "token is a 5-segment compact JWE (not a bare 3-segment JWS)" \
  || fail "token is not a compact JWE: $ADMIN_TOKEN"

# The whole point of the JWE layer: the claims must NOT be recoverable without the key.
# Checks EVERY segment, not just one: a plain JWS would yield JSON from its payload segment,
# and this also catches a claim accidentally replicated onto the outer protected header.
# (An earlier version of this check looked only at segment 2, which in a JWE is the encrypted
# key rather than the payload, so it could have passed without proving much.)
if node -e '
  const [, token] = process.argv;
  const needles = ["users:read", "tenant-admin", "permissions", "\"tid\"", "\"sub\""];
  for (const seg of token.split(".")) {
    let text = "";
    try { text = Buffer.from(seg, "base64url").toString("utf8"); } catch { continue; }
    if (needles.some((n) => text.includes(n))) {
      process.stderr.write("leaked in segment: " + text.slice(0, 200));
      process.exit(0); // exit 0 == leak found
    }
  }
  process.exit(1); // exit 1 == nothing leaked
' "$ADMIN_TOKEN" 2>/dev/null; then
  fail "token leaks claims without the key -- NOT ENCRYPTED"
else
  pass "no segment of the token reveals claims without the encryption key"
fi

DECODED=$(node "$REPO_ROOT/scripts/decode-token.mjs" "$ADMIN_TOKEN")
[ "$(printf '%s' "$DECODED" | jq -r '.outerHeader.cty')" = "JWT" ] \
  && pass "outer JWE header carries cty=JWT (RFC 7519 s5.2)" \
  || fail "outer cty wrong: $DECODED"
[ "$(printf '%s' "$DECODED" | jq -r '.outerHeader.alg + "/" + .outerHeader.enc')" = "A256KW/A256GCM" ] \
  && pass "outer JWE is A256KW + A256GCM" \
  || fail "unexpected JWE algorithms: $DECODED"
[ "$(printf '%s' "$DECODED" | jq -r '.innerSegments')" = "3" ] \
  && pass "plaintext of the JWE is itself a 3-segment JWS" \
  || fail "inner token is not a JWS: $DECODED"
[ "$(printf '%s' "$DECODED" | jq -r '.innerHeader.typ')" = "crbk-at+jwt" ] \
  && pass "inner JWS is explicitly typed, and not the RFC 9068 at+jwt it does not conform to" \
  || fail "unexpected inner typ: $DECODED"

step "6. The verified claims carry tenant id, user id, roles and permissions"
CLAIMS=$(printf '%s' "$DECODED" | jq '.claims')
[ "$(printf '%s' "$CLAIMS" | jq -r '.tid')" = "$TENANT_A_ID" ] \
  && pass "tid claim is the tenant id" \
  || fail "tid claim wrong: $CLAIMS"
printf '%s' "$CLAIMS" | jq -e '.sub | test("^[0-9a-f-]{36}$")' >/dev/null 2>&1 \
  && pass "sub claim is the user id (uuid)" \
  || fail "sub claim is not a uuid: $CLAIMS"
[ "$(printf '%s' "$CLAIMS" | jq -r '.roles | index("tenant-admin") // "no"')" != "no" ] \
  && pass "roles claim contains tenant-admin" \
  || fail "roles claim wrong: $CLAIMS"
[ "$(printf '%s' "$CLAIMS" | jq -r '.permissions | sort | join(",")')" \
    = "roles:manage,users:read,users:write" ] \
  && pass "permissions claim carries the seeded grants" \
  || fail "permissions claim wrong: $CLAIMS"
[ "$(printf '%s' "$CLAIMS" | jq -r '.iss')" = "compliance-ready-backend-kit" ] \
  && pass "iss claim is set and verified on the way back in" \
  || fail "iss claim wrong: $CLAIMS"
[ "$(printf '%s' "$CLAIMS" | jq -r '.aud')" = "compliance-kit-api" ] \
  && pass "aud claim is set and verified on the way back in" \
  || fail "aud claim wrong: $CLAIMS"

step "7. Seeded admin can read users (RBAC allows)"
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 200 "$status" "GET /users as tenant-admin"
[ "$(jq -r '.data | length' /tmp/smoke-body)" = "1" ] \
  && pass "tenant contains exactly its seeded admin" \
  || fail "unexpected user count: $(cat /tmp/smoke-body)"

step "8. Resolve the same tenant by UUID as well as by slug"
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A_ID" -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 200 "$status" "GET /users with the tenant UUID in x-tenant-id"

step "9. A registered user holds no roles, so is denied (RBAC denies)"
status=$(req POST /auth/register \
  "{\"email\":\"plain@$TENANT_A.example\",\"password\":\"$USER_PASSWORD\"}" \
  -H "x-tenant-id: $TENANT_A")
expect_status 201 "$status" "POST /auth/register"

status=$(req POST /auth/register \
  "{\"email\":\"plain@$TENANT_A.example\",\"password\":\"$USER_PASSWORD\"}" \
  -H "x-tenant-id: $TENANT_A")
expect_status 409 "$status" "POST /auth/register with a duplicate email"

USER_TOKEN=$(login "$TENANT_A" "plain@$TENANT_A.example" "$USER_PASSWORD")
[ "$(token_claims "$USER_TOKEN" | jq -r '.permissions | length')" = "0" ] \
  && pass "registered user's token carries no permissions" \
  || fail "registered user has permissions: $(token_claims "$USER_TOKEN")"
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer $USER_TOKEN")
expect_status 403 "$status" "GET /users without the users:read permission"

step "10. Wrong password and unknown user both fail the same way"
status=$(req POST /auth/login "{\"email\":\"$ADMIN_A\",\"password\":\"wrong-password-entirely\"}" \
  -H "x-tenant-id: $TENANT_A")
expect_status 401 "$status" "POST /auth/login with a wrong password"
status=$(req POST /auth/login \
  "{\"email\":\"nobody@$TENANT_A.example\",\"password\":\"$USER_PASSWORD\"}" \
  -H "x-tenant-id: $TENANT_A")
expect_status 401 "$status" "POST /auth/login for a nonexistent user"

step "11. Tenant isolation: A's users are invisible from B"
B_TOKEN=$(login "$TENANT_B" "$ADMIN_B" "$ADMIN_PASSWORD")
status=$(req GET /users "" -H "x-tenant-id: $TENANT_B" -H "authorization: Bearer $B_TOKEN")
expect_status 200 "$status" "GET /users as tenant B admin"
# Counted rather than tested with `jq -e`, because a jq *error* also exits non-zero and would
# have taken the "no breach" branch. Comparing an explicit count means a broken query fails
# the check instead of silently passing it.
a_leaked=$(jq -r --arg a "$TENANT_A" '[.data[].email | select(contains($a))] | length' /tmp/smoke-body 2>/dev/null)
[ "$a_leaked" = "0" ] \
  && pass "tenant B sees none of tenant A's users" \
  || fail "tenant B can see $a_leaked of tenant A's users -- ISOLATION BREACH: $(cat /tmp/smoke-body)"
# Tenant A has 2 users by now (seeded admin + registered user) and B has only its admin, so
# this simultaneously proves B's list is non-empty and did not pick up A's registration.
[ "$(jq -r '.data | length' /tmp/smoke-body)" = "1" ] \
  && pass "tenant B holds exactly its own 1 user while tenant A holds 2" \
  || fail "unexpected user count in tenant B: $(cat /tmp/smoke-body)"

step "12. A token minted for tenant A is rejected when addressed to tenant B"
# Database-per-tenant alone does NOT cover this: the query would be routed correctly to
# tenant B's database, so no data crosses between tenants, but the caller would be acting
# inside a tenant they hold no account in, carrying tenant A's permissions. The check lives in
# AccessTokenGuard, in the same step as authentication, so it cannot be omitted by assembling
# a guard chain wrongly. Regression test for that.
status=$(req GET /users "" -H "x-tenant-id: $TENANT_B" -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 401 "$status" "GET /users with a token minted for a different tenant"
[ "$(jq -r '.code' /tmp/smoke-body)" = "CROSS_TENANT_TOKEN" ] \
  && pass "rejected with CROSS_TENANT_TOKEN" \
  || fail "unexpected error body: $(cat /tmp/smoke-body)"

step "13. Malformed and forged tokens are rejected"
# The fixtures below are built with the service's real keys. If a key did not resolve, they
# would still be built, still be rejected, and still "pass" while proving nothing. Check first.
SIGN_KEY=$(key_from_env_or_file JWT_SIGNING_KEY)
ENC_KEY=$(key_from_env_or_file JWT_ENCRYPTION_KEY)
if [ "${#SIGN_KEY}" = "43" ] && [ "${#ENC_KEY}" = "43" ]; then
  pass "resolved both signing and encryption keys, so the forgery fixtures are meaningful"
else
  fail "could not resolve keys (signing=${#SIGN_KEY} chars, encryption=${#ENC_KEY} chars). Set JWT_SIGNING_KEY and JWT_ENCRYPTION_KEY, or provide a .env"
fi
# A bare JWS must not be accepted where a JWE is expected. This is the RFC 8725 s2.3
# signature-stripping shape: if verification decrypted without then verifying, or accepted
# an unencrypted token, this would pass.
# Signed with the REAL signing key and carrying the REAL tenant id, so the only thing
# wrong with it is the missing encryption layer. That is what makes this a real test.
BARE_JWS=$(node -e '
const [,sk,iss,aud,tid]=process.argv;
import("jose").then(async ({SignJWT})=>{
  const t=await new SignJWT({sub:"00000000-0000-4000-8000-000000000000",tid,roles:["tenant-admin"],permissions:["users:read"]})
    .setProtectedHeader({alg:"HS256",typ:"crbk-at+jwt"}).setIssuer(iss).setAudience(aud)
    .setIssuedAt().setExpirationTime("15m").sign(new Uint8Array(Buffer.from(sk,"base64url")));
  process.stdout.write(t);
});' "$(key_from_env_or_file JWT_SIGNING_KEY)" \
   compliance-ready-backend-kit compliance-kit-api "$TENANT_A_ID" 2>/dev/null)
[ "$(printf '%s' "$BARE_JWS" | awk -F. '{print NF}')" = "3" ] \
  && pass "negative-test fixture is a real signed JWS (test is not vacuous)" \
  || fail "could not build the bare-JWS fixture: $BARE_JWS"
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer $BARE_JWS")
expect_status 401 "$status" "a correctly signed but UNENCRYPTED token is refused"

status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer not-a-token")
expect_status 401 "$status" "garbage bearer token"
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: $ADMIN_TOKEN")
expect_status 401 "$status" "token with no Bearer scheme"
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A")
expect_status 401 "$status" "no Authorization header at all"
# Flip a byte inside a segment and re-encode. Note this decodes to bytes first rather than
# editing the base64url text: the final character of a segment carries only a couple of
# significant bits, so changing it can re-decode to the identical bytes and prove nothing.
# Segments of a compact JWE are: header.encryptedKey.iv.ciphertext.tag
# Note the argv slice: under `node -e`, process.argv[1] is the first user argument, not a
# script path, so there is exactly one element to skip.
tamper_segment() {
  node -e '
    const [, token, index] = process.argv;
    const parts = token.split(".");
    const buf = Buffer.from(parts[Number(index)], "base64url");
    buf[0] ^= 0xff;
    parts[Number(index)] = buf.toString("base64url");
    process.stdout.write(parts.join("."));
  ' "$1" "$2"
}

# THE attack this design exists to stop (RFC 8725 s2.3, incorrect composition of encryption
# and signature). The token below is encrypted with the REAL encryption key and has a correct
# outer header, so it decrypts perfectly. Only its INNER signature is forged. An
# implementation that decrypted and trusted the result would accept it and hand the caller
# full admin permissions. Verifying the inner JWS separately is the only thing that catches it.
FORGED=$(node -e '
const [,ek,iss,aud,tid]=process.argv;
import("jose").then(async ({SignJWT,CompactEncrypt})=>{
  const wrongSigningKey=new Uint8Array(32).fill(9);
  const jws=await new SignJWT({sub:"00000000-0000-4000-8000-000000000000",tid,
      roles:["tenant-admin"],permissions:["users:read","users:write","roles:manage"]})
    .setProtectedHeader({alg:"HS256",typ:"crbk-at+jwt"})
    .setIssuer(iss).setAudience(aud).setIssuedAt().setExpirationTime("15m")
    .sign(wrongSigningKey);
  const jwe=await new CompactEncrypt(new TextEncoder().encode(jws))
    .setProtectedHeader({alg:"A256KW",enc:"A256GCM",cty:"JWT",typ:"crbk-at+jwt"})
    .encrypt(new Uint8Array(Buffer.from(ek,"base64url")));
  process.stdout.write(jwe);
});' "$ENC_KEY" compliance-ready-backend-kit compliance-kit-api "$TENANT_A_ID" 2>/dev/null)

# Prove the outer layer is genuinely valid, so a 401 can only have come from the signature
# check. Without this the test could pass for the boring reason that the token was malformed.
if node -e '
const [,tok,ek]=process.argv;
import("jose").then(async ({compactDecrypt})=>{
  const {protectedHeader}=await compactDecrypt(tok,new Uint8Array(Buffer.from(ek,"base64url")),
    {keyManagementAlgorithms:["A256KW"],contentEncryptionAlgorithms:["A256GCM"]});
  if(protectedHeader.cty!=="JWT") process.exit(1);
}).catch(()=>process.exit(1));' "$FORGED" "$ENC_KEY" 2>/dev/null; then
  pass "forged-token fixture decrypts cleanly (so the next check tests the signature, not the JWE)"
else
  fail "forged-token fixture does not decrypt; the next check would be vacuous"
fi
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer $FORGED")
expect_status 401 "$status" "valid JWE wrapping a FORGED inner JWS is refused (RFC 8725 s2.3)"

for segment in "3:ciphertext" "4:authentication tag" "1:encrypted key"; do
  index="${segment%%:*}"
  label="${segment#*:}"
  TAMPERED=$(tamper_segment "$ADMIN_TOKEN" "$index")
  [ "$TAMPERED" != "$ADMIN_TOKEN" ] \
    || fail "tamper of $label did not change the token (test would be vacuous)"
  status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer $TAMPERED")
  expect_status 401 "$status" "tampered $label"
done

step "14. Unknown tenant and missing header are rejected"
status=$(req GET /users "" -H "x-tenant-id: no-such-tenant-anywhere" \
  -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 404 "$status" "GET /users with an unknown tenant slug"
status=$(req GET /users "" -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 404 "$status" "GET /users with no x-tenant-id header"

step "15. Response contract: RFC 9457 problem details and the success envelope"

# Every 2xx body is { success, data, meta }; every error is application/problem+json. Before
# this contract existed the API emitted three different error shapes, and `error` meant a
# machine code in one of them and a human phrase in the other two.
status=$(req GET /users "" -H "x-tenant-id: $TENANT_A" -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 200 "$status" "GET /users for envelope inspection"
jq -e '.success == true and has("data") and has("meta")' /tmp/smoke-body >/dev/null 2>&1 \
  && pass "2xx body is { success, data, meta }" \
  || fail "success envelope missing or wrong: $(cat /tmp/smoke-body)"
[ "$(jq -r '.meta.totalCount' /tmp/smoke-body)" = "2" ] \
  && pass "meta.totalCount is populated for a list response" \
  || fail "meta.totalCount wrong: $(cat /tmp/smoke-body)"
jq -e '.data | type == "array"' /tmp/smoke-body >/dev/null 2>&1 \
  && pass "data holds the resource itself, unwrapped" \
  || fail "data is not the array: $(cat /tmp/smoke-body)"

# `success` has to appear on BOTH shapes or it discriminates nothing: a field that is only ever
# true tells a client precisely as much as its absence would.
status=$(req GET /users "" -H "x-tenant-id: definitely-no-such-tenant" \
  -H "authorization: Bearer $ADMIN_TOKEN")
[ "$(jq -r '.success' /tmp/smoke-body)" = "false" ] \
  && pass "error bodies carry success:false, so success is a real discriminator" \
  || fail "error body has no success:false: $(cat /tmp/smoke-body)"

content_type() { curl -sS -o /dev/null -D- "$@" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="content-type"{print $2}'; }

ct=$(content_type -X POST "$BASE_URL/auth/login" -H 'content-type: application/json' \
  -H 'x-tenant-id: definitely-no-such-tenant' -d '{"email":"a@b.co","password":"x"}')
case "$ct" in
  application/problem+json*) pass "errors are served as application/problem+json" ;;
  *) fail "wrong content-type on an error: $ct" ;;
esac

# Validation: 422 with a per-field errors array, JSON Pointers and all (RFC 9457 s3.2).
status=$(req POST /tenants '{"slug":"BAD SLUG","name":"x","extra":1}')
expect_status 422 "$status" "invalid field values give 422, not 400"
jq -e '.code == "VALIDATION_FAILED" and (.errors | length) >= 3' /tmp/smoke-body >/dev/null 2>&1 \
  && pass "422 body carries the errors extension" \
  || fail "errors extension missing: $(cat /tmp/smoke-body)"
jq -e '[.errors[].pointer] | index("#/slug") != null' /tmp/smoke-body >/dev/null 2>&1 \
  && pass "each field problem carries a JSON Pointer (#/slug)" \
  || fail "no JSON Pointer for slug: $(cat /tmp/smoke-body)"
jq -e '[.errors[].pointer] | index("#/extra") != null' /tmp/smoke-body >/dev/null 2>&1 \
  && pass "unknown properties are rejected, not ignored" \
  || fail "unknown property not reported: $(cat /tmp/smoke-body)"

# A body that cannot be parsed is a DIFFERENT problem from one whose values are wrong, so a
# client can tell "my serialiser is broken" from "my data is wrong".
status=$(curl -sS -o /tmp/smoke-body -w '%{http_code}' -X POST "$BASE_URL/tenants" \
  -H 'content-type: application/json' -d '{not json')
expect_status 400 "$status" "unparseable body gives 400, distinct from 422"
[ "$(jq -r '.code' /tmp/smoke-body)" = "MALFORMED_REQUEST" ] \
  && pass "unparseable body reports MALFORMED_REQUEST" \
  || fail "unexpected code for malformed body: $(cat /tmp/smoke-body)"

# All five RFC 9457 members plus our two extensions, on an arbitrary error.
status=$(req GET /users "" -H "x-tenant-id: definitely-no-such-tenant" \
  -H "authorization: Bearer $ADMIN_TOKEN")
expect_status 404 "$status" "unknown tenant for problem-member inspection"
jq -e 'has("type") and has("title") and has("status") and has("detail") and has("instance")' \
  /tmp/smoke-body >/dev/null 2>&1 \
  && pass "all five RFC 9457 members are present" \
  || fail "missing RFC 9457 members: $(cat /tmp/smoke-body)"
[ "$(jq -r '.status' /tmp/smoke-body)" = "404" ] \
  && pass "advisory status member matches the real status line (RFC 9457 s3.1.2)" \
  || fail "status member disagrees with the status line: $(cat /tmp/smoke-body)"
jq -e '.instance | test("^urn:uuid:[0-9a-f-]{36}$")' /tmp/smoke-body >/dev/null 2>&1 \
  && pass "instance is a per-occurrence urn:uuid" \
  || fail "instance is not a urn:uuid: $(cat /tmp/smoke-body)"
[ "$(jq -r '.instance' /tmp/smoke-body)" = "urn:uuid:$(jq -r '.traceId' /tmp/smoke-body)" ] \
  && pass "traceId matches the instance uuid" \
  || fail "traceId and instance disagree: $(cat /tmp/smoke-body)"
# The type URI must resolve to a heading that exists in docs/problems.md, or the RFC's promise
# that dereferencing it yields documentation is a lie.
anchor=$(jq -r '.type' /tmp/smoke-body | sed 's/.*#//')
[ "$anchor" = "tenant-not-found" ] \
  && pass "type URI anchor is derived from the code" \
  || fail "unexpected type anchor: $anchor"
grep -q "^### \`$anchor\`" "$REPO_ROOT/docs/problems.md" \
  && pass "docs/problems.md documents the '$anchor' anchor the type URI points at" \
  || fail "docs/problems.md has no section for anchor '$anchor'"

step "Result"
if [ "$FAILURES" -eq 0 ]; then
  printf '  \033[32mAll checks passed.\033[0m Tenants created: %s, %s\n' "$TENANT_A" "$TENANT_B"
  printf '  Databases: tenant_%s, tenant_%s\n' "${TENANT_A//-/_}" "${TENANT_B//-/_}"
else
  printf '  \033[31m%s check(s) failed.\033[0m\n' "$FAILURES"
  exit 1
fi
