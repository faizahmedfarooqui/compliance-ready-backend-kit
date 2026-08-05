# Key management

The `config_keys` registry, the lifecycle Postgres enforces, rotation, and the published JWKS.

## Where keys live

In `config_keys`, in the **master** database, holding **wrapped** key material and never plaintext.

The only key in configuration is `KEY_ENCRYPTION_KEY`, the KEK that wraps everything else. That is the
point of envelope encryption: a key in config is a key in every deploy manifest, CI secret store and
developer shell, whereas one KEK can be moved into a KMS, an HSM or an enclave without touching the rest
of the system.

Each row carries:

| Column | Notes |
| --- | --- |
| `kid` | **`TEXT`, not `uuid`.** See below |
| `purpose` | `token_signing` or `token_encryption` |
| `algorithm` | `ES256` or `A256KW`, paired to purpose by a CHECK constraint |
| `status` | `pending`, `active`, `retiring`, `revoked` |
| `wrapped_material` | AES-256-GCM ciphertext, AAD bound to `purpose` and `kid` |
| `public_jwk` | Required for asymmetric keys, refused for symmetric ones |
| `not_after` | When a retiring key stops verifying |

### Keys are deployment-wide, not per tenant

Which tenant a token belongs to is the `tid` claim **inside the ciphertext**. A per-tenant key would
therefore require knowing the tenant before the token can be decrypted, and every way to get it is
broken: reading an unverified claim is circular, putting the tenant in a header leaks it on every
request, and letting the caller name the key is attacker-directed key selection.

So keys live in the master, not in tenant databases.

### `kid` is `TEXT` for a security reason

RFC 7517 §4.5 makes `kid` an arbitrary case-sensitive string. Two consequences:

1. A `uuid` column would normalise case, contradicting the spec.
2. An attacker sending a non-uuid `kid` against a `uuid` column raises Postgres 22P02, which surfaces as
   a **500 and an error-log flood** instead of a clean 401.

That is the same bug class as the `resolveTenant` slug-versus-uuid problem described in
[multi-tenancy](multi-tenancy.md#resolving-a-tenant).

## The lifecycle is enforced by Postgres

Not by application code, because in application code "exactly one active key" is a race between two pods
in one maintenance window.

- **A partial unique index** permits exactly one `active` key per purpose.
- **A CHECK constraint pairs purpose to algorithm.** Without it, `token_signing` + `A256KW` would hand 32
  raw bytes to a signature check.
- **A CHECK requires a public JWK for asymmetric keys** and refuses one for symmetric keys.
- **A CHECK refuses a `revoked` row that still holds material.** Revocation destroys the key or it is not
  revocation.

Each of these was verified by trying to violate it, which is the only way to know a constraint is doing
anything.

`not_after` is enforced **at resolve time**, not only by a sweeper, so an expired key stops verifying even
if no cleanup job has run.

## The in-memory snapshot, and why it exists

`KeyRegistryService` holds a snapshot of the active and retiring keys, and the resolvers handed to `jose`
read only from it.

This is required, not an optimisation. `jose` calls a key resolver with the **attacker-controlled `kid`
from an unverified header** (RFC 8725 §2.9). An async resolver would let a forged kid drive a database
query or a KMS unwrap per unauthenticated request, which is a remote amplification primitive. A
synchronous resolver over an in-memory map cannot be used that way.

The snapshot is refreshed **two ways, and both are needed**:

- **On a cooldown-limited miss.** An unrecognised kid triggers at most one reload per 30s, the same shape
  `jose`'s own `createRemoteJWKSet` uses. That bounds what a forged kid can cause to one query per
  window.
- **On a 60s timer.** Refresh-on-miss alone **silently misses a rotation**, because a stale-but-still-valid
  active key produces no misses at all: the old key keeps verifying and the service never learns there is a
  new one. This was found by rotating against a running server, not by reasoning about it.

The refresh is deliberately invisible to the resolvers. `TokenService.verify` calls `refreshIfStale()`
itself, between a failed verification and its single retry, so the resolvers stay pure and synchronous.

## Operator commands

```bash
pnpm keys:init                          # bootstrap a deployment: one signing + one encryption key
pnpm keys:rotate --purpose signing      # mint a new active key, retire the previous one
pnpm keys:list                          # every key, its status, and any overlap window
pnpm keys:revoke --kid <kid> --reason "..."
pnpm keys:decode <token>                # fully verify a token and print its claims and headers
```

### Bootstrap and rotation are CLIs, never migrations

A migration is committed to git and replayed against Prisma's shadow database, so **any key a migration
generated would be identical in every environment and therefore public.** Key generation is an
operational act, so it lives in an operator command.

This is why `pnpm keys:init` is a required step in [getting started](getting-started.md): the table
starts empty, and a service with no active signing key boots fine and fails every login.

### Rotation is graceful

`pnpm keys:rotate` runs in one transaction: the new key becomes `active`, the previous one becomes
`retiring` with `not_after = now + accessTtl + clockTolerance`.

That window is exactly right and both directions of getting it wrong are bad. Shorter kills tokens that
are still legitimately valid; absent means the overlap never ends and a compromised old key keeps working
forever.

Revoking the **active** key is refused, because it would leave the service unable to issue tokens at all.
Revoking a retiring key is allowed and destroys its material.

CI exercises rotation and revocation against real Postgres, including asserting that revoking the active
key fails, because what makes rotation correct is the database constraints rather than the code.

## The published JWKS

Public signing keys are served at **`/.well-known/jwks.json`**, at the **origin root**, per RFC 8615.

Two things had to be special-cased for that:

- The route is **excluded from the global `api` prefix**. A well-known URI nested under `/api` is not a
  well-known URI.
- The route is marked `@RawResponse()` so the success envelope does not wrap it. Wrapping a JWK Set in
  `{ success, data }` breaks every standard consumer, including `jose`'s own `createRemoteJWKSet`.

That second bug was invisible from inside the process: the handler was correct and a unit test passed.
Only the bytes on the wire showed `{"success":true,"data":{"keys":[...]}}`. A smoke assertion now checks
the wire format, and another asserts the document contains no private scalar (`d`).

### The outer layer is a shared secret

Worth being blunt, because the presence of a JWKS invites the wrong conclusion.

A published JWKS does **not** let a third party verify these tokens with only public keys. The outer JWE
uses symmetric `A256KW`, so the JWKS alone yields `ERR_JWS_INVALID`. Verification requires being handed
the `A256KW` key too, and that key grants **decryption of every token** the deployment has ever issued,
though still not the ability to mint one.

`ECDH-ES` for the outer layer would fix this and is not implemented. Until it is, treat token
verification as something only the issuing deployment can do.

## The `KeyProvider` port

`packages/crypto/src/key-provider.ts` defines the seam:

```ts
interface KeyProvider {
  wrap(plaintext: Uint8Array, ctx: KeyContext): Promise<Uint8Array>;
  unwrap(ciphertext: Uint8Array, ctx: KeyContext): Promise<Uint8Array>;
}
```

`LocalKeyProvider` implements it with AES-256-GCM, binding the AAD to `purpose` and `kid` so a wrapped
signing key cannot be replayed as an encryption key or under a different kid.

A KMS, HSM or enclave adapter is **a new file implementing this interface**, not a refactor. That was the
whole reason for the port.

## What is not done yet

**The KEK is still in configuration.** Envelope encryption, the lifecycle, rotation and the JWKS all
exist, but no KMS or HSM adapter is written, so the KEK is only as protected as the process and its config
store.

This is why COMPLIANCE.md marks key management **Partial** rather than Implemented, and it is the reason
that row should not be cited against a requirement calling for a secure cryptographic device (PCI Req 3.6,
3.7). Do not read the presence of envelope encryption as satisfying that.

Also missing: no automatic rotation schedule (rotation is an operator action), and no documented 12-month
cryptographic inventory review (PCI 12.3.3).

## Control mapping

Key management maps to HIPAA 164.312(a)(2)(iv), PCI-DSS Req 3 (3.6, 3.7, marked unverified), and SOC 2
CC6.1, with status **Partial** for the reason above. See [COMPLIANCE.md](../COMPLIANCE.md) and
[the compliance guide](compliance.md).
