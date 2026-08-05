# Authentication

Nested JWT access tokens: what they are, why they are built this way, and how they are verified.

## The token format

An access token is a **nested JWT**: signed first, then encrypted.

```
inner JWS   alg: ES256            typ: crbk-at+jwt   kid: <signing key id>
outer JWE   alg: A256KW           enc: A256GCM
                                  cty: JWT           typ: crbk-at+jwt   kid: <encryption key id>
```

Claims are small and tenant-scoped:

```json
{
  "sub": "<user id within the tenant>",
  "tid": "<tenant id>",
  "roles": ["tenant-admin"],
  "permissions": ["users:read", "users:write", "roles:manage"],
  "iss": "...", "aud": "...", "iat": 0, "exp": 0
}
```

Implemented with `jose` directly, in `packages/crypto/src/tokens.ts`. That module is **pure**: it holds
no keys and reads no database. Keys arrive through resolver functions.

## Why every part of that is the way it is

### Encrypted, not just signed

A plain JWS access token is readable by anything that handles it: a browser extension, a log
aggregator, an error tracker, a proxy. These tokens carry the tenant id, the user id, and the full
permission list, which is a useful map for anyone deciding what to attack. Encrypting the outer layer
means the claims are not readable without the key.

### ES256 inside, not HS256

A symmetric inner signature means **anything that can verify can also mint**. Handing a second service
the verification key would hand it the power to forge `roles` for any tenant. With ES256 the private
key signs and the public key verifies, so verification can be distributed without distributing the
ability to issue.

Do not "simplify" this back to HS256.

### `cty: "JWT"` on the outer header

RFC 7519 §5.2 requires it for a nested JWT: the value tells a recipient the plaintext is itself a JWT
and must be processed again. Verification checks it.

### `typ` is `crbk-at+jwt`, not `at+jwt`

RFC 9068 defines `at+jwt` as an assertion that the token conforms to the OAuth 2.0 JWT access token
profile. This kit does not meet that profile: no `client_id`, no RS256 support. Claiming the type would
be a false statement about conformance in a machine-readable field, so the kit uses its own.

### Both layers carry a `kid`

So rotation can be graceful. A token is verifiable as long as the keys it names are still resolvable,
which lets a retiring key keep working for the lifetime of tokens it signed. See
[key management](key-management.md).

## Verification

`verifyNestedToken` does, in order:

1. Decrypt the outer JWE using the encryption key named by the outer `kid`.
2. Check the outer `cty` is `JWT`.
3. **Verify the inner JWS signature** using the signing key named by the inner `kid`.
4. Check `typ`, `iss`, `aud`, `exp` and `iat`, with the configured clock tolerance.

**Step 3 is not optional and `compactDecrypt` alone is not verification.** RFC 8725 §2.3 is explicit:
successfully decrypting a JWE tells you the sender had the encryption key, and nothing about the claims
inside. Skip the inner signature check and anyone holding the encryption key can forge any claim they
like. Four smoke assertions guard this, including one that presents a valid JWE wrapping a forged inner
JWS and requires a 401.

### There is deliberately no decode-without-verify helper

`verifyNestedToken` returns `{ claims, outerHeader, innerHeader }`. The headers are a **product of
successful verification** and are obtainable no other way, on purpose. A `decodeToken` helper that
skipped verification would be the RFC 8725 §2.3 mistake wearing a helpful name, and it would eventually
be called somewhere that mattered.

`pnpm keys:decode <token>` exists for inspection and performs full verification before printing
anything.

### Key resolvers must be synchronous

`SigningKeyResolver` and `EncryptionKeyResolver` are `(kid: string) => ... | undefined`. Synchronous,
and that is a security property rather than an ergonomic choice.

`jose` calls the resolver with the **attacker-controlled `kid` from an unverified header** (RFC 8725
§2.9), before anything has been checked. An async resolver would therefore let a forged kid drive a
database query or a KMS unwrap **per unauthenticated request**, which is a remote amplification
primitive.

So `KeyRegistryService` keeps an in-memory snapshot and the resolvers read only from it. The refresh
happens elsewhere: `TokenService.verify` calls `refreshIfStale()` itself, between a failed verification
and its single retry, so the resolvers stay pure.

### Two separately-typed resolvers

`SigningKeyResolver` returns a `CryptoKey`; `EncryptionKeyResolver` returns a `Uint8Array`. Different
types so that a signing lookup **structurally cannot** return the symmetric encryption key. On top of
that, both the header `alg` and the stored `algorithm` column are checked against an allow-list, because
RFC 8725 §3.1 requires that each key be used with exactly one algorithm and that this be enforced at the
point of use.

## The guards

### `AccessTokenGuard`

A plain `CanActivate`. It extracts the bearer token, verifies both layers, and **requires
`claims.tid === request.tenant.id`**.

That cross-tenant check is inside this guard, in the same step as authentication, and it fails closed.
Both properties matter:

- **Same step.** It was originally a separate guard, which was wrong, because a guard can be left out
  of a chain. A token for tenant A used with `x-tenant-id: B` must be rejected: database-per-tenant
  routes the query to B correctly so no data crosses, but the caller would be acting inside a tenant
  they hold no account in, carrying A's permissions.
- **Fails closed.** No resolved tenant throws rather than passing.

The bearer parse is stricter than it looks. A repeated `Authorization` header arrives as an array, and
rather than pick one the guard refuses: which one a proxy forwards is not something to leave to chance.

Every failure raises the same `InvalidAccessTokenError`, whatever the cause. Telling a caller which
check failed tells an attacker which part of a forged token to fix next.

### No Passport, and it cannot come back

`@nestjs/jwt`, `@nestjs/passport`, `passport` and `passport-jwt` were removed and must not return:

- `@nestjs/jwt` wraps `jsonwebtoken`, which is JWS-only and cannot produce a JWE at all.
- `passport-jwt` reads the token through a **synchronous** extractor (`var token =
  self._jwtFromRequest(req)`), which cannot await a decryption.

Doing it in a plain guard also drops four dependencies in favour of `jose`, which has none.

## Login

`POST /api/auth/login` with `x-tenant-id`. Rate limited to 20 per minute per client, and separately
throttled on failure.

What happens on the way through, and why:

- **Email is normalised** before lookup, so case and whitespace differences do not create a second
  account or a failed login for the same person.
- **Timing is equalised with a decoy hash.** An unknown email verifies the supplied password against a
  dummy hash so that "no such user" and "wrong password" take the same time. Without it, response
  latency enumerates valid accounts.
- **Both failures return the identical `INVALID_CREDENTIALS`** for the same reason.
- **Transparent rehashing.** After a successful verification, if the stored hash used weaker parameters
  than the current `ARGON2_OPTIONS`, it is rehashed. Raising a work factor otherwise protects only
  passwords set after the change, leaving every existing credential at the old strength indefinitely.
- **Login throttling** counts failures per account and per source address, clears on success, and is
  separate from the request rate limiter. Ten failures in fifteen minutes by default. Counting only
  failures and clearing on success means a user who mistypes twice and then succeeds is never nearer a
  limit. See [rate limiting](rate-limiting.md#login-throttling-is-a-different-control).
- **A login success, failure, or throttle is recorded** to the tenant's audit chain.

### Password storage

Argon2id, with explicitly declared parameters in `packages/crypto/src/passwords.ts`:

```
type: argon2id   memoryCost: 19456 (19 MiB)   timeCost: 2   parallelism: 1
```

These are the OWASP Password Storage Cheat Sheet's recommended second configuration, pinned here rather
than left to library defaults so that a dependency upgrade cannot silently change a security property.
`verifyPassword` returns false rather than throwing on a malformed or unrecognised hash, so a corrupt
row is a failed login rather than a 500.

## Known limitations

- **Permissions are baked into the token at login.** A permission change takes effect when the token
  expires, up to `JWT_ACCESS_TTL_SECONDS` (900s default) later. There is no revocation list.
- **Tokens are not sender-constrained.** Encrypted, but still bearer credentials: whoever holds one can
  use it. mTLS (RFC 8705) or DPoP (RFC 9449) is the real control and neither is implemented.
- **The outer JWE layer is a shared secret.** See
  [key management](key-management.md#the-outer-layer-is-a-shared-secret).
- **No MFA, no passkeys, no WebAuthn.** COMPLIANCE.md marks that row Not implemented; it is the next
  milestone.
- **There are no refresh tokens.** Clients re-authenticate.

## Control mapping

Access-token confidentiality maps to HIPAA 164.308(a)(1)(ii)(B), PCI Req 6 (6.2.4) and Req 12 (12.3.3),
SOC 2 CC6.1. Password storage maps to HIPAA 164.312(d), PCI Req 8 (8.3.2), SOC 2 CC6.1. Both are marked
Implemented. The MFA row is not. See [COMPLIANCE.md](../COMPLIANCE.md).
