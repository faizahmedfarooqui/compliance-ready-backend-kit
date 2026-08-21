# Changelog

Notable changes per release. Written for someone deciding whether to adopt or upgrade, so it says what
changed and what it means rather than restating commit subjects.

Versions follow [semantic versioning](https://semver.org/). The kit is pre-1.0, so minor versions may
change behaviour; each entry says so where it does.

**Statuses in this file mean what they mean in [COMPLIANCE.md](./COMPLIANCE.md).** A capability listed
here as added is a capability that file marks Implemented, and `pnpm verify:claims` will reproduce the
evidence for it. Nothing is listed here that cannot be checked that way.

## v0.2.0

The first tagged release. v0.1 existed as a milestone and was never tagged, so the versions in
`package.json` moved 0.1.0 to 0.2.0 with this release rather than at the point the milestone was
finished; the README said as much while that was true.

Sixteen mapped controls, of which **nine are implemented**, three partial, two not implemented, and two
deliberately outside this repository.

### Added

- **Append-only, hash-chained audit log.** One independent chain per database, plus a separate
  control-plane chain in the master, because audit records about a tenant's users are that tenant's data
  and Postgres advisory locks are per-database so a chain spanning tenants could not be serialised at
  all. Enforcement is in the database rather than the application: row triggers refusing UPDATE and
  DELETE, a statement trigger refusing TRUNCATE (row triggers never fire for TRUNCATE), REVOKE of those
  privileges, and CHECK constraints pinning the hash widths and metadata shape. `UNIQUE(prev_hash)` makes
  a fork impossible rather than unlikely.
- **A restricted database role** (`packages/db/sql/restricted-role.sql`) that turns the REVOKE layer from
  documentation of intent into an enforced boundary: UPDATE, DELETE and TRUNCATE on `audit_events` then
  fail with SQLSTATE 42501 before the trigger is consulted. It cannot provision tenants, and the reason
  is a genuine conflict rather than an oversight; see [deployment](docs/deployment.md#the-restricted-role).
- **A container image**, with separate `runtime` and `migrator` targets so the container that serves
  traffic does not also carry the tool that can rewrite the schema.
- **Rate limiting and login throttling** on Redis, evaluated atomically in a Lua sliding window. Fails
  open on request tiers for availability and loudly reports when it does.
- **Request-level denial-of-service limits**: request timeout, body size cap, connection timeout, and a
  keep-alive bound.
- **An authenticated control plane.** Tenant provisioning requires a bearer credential, and the limiter
  runs before authentication so a rejected call is still counted.
- **A key registry with rotation and a published JWKS.** Keys live wrapped in `config_keys`, indexed by
  `kid`, with a pending/active/retiring/revoked lifecycle enforced by database constraints rather than
  application code. `/.well-known/jwks.json` publishes the public halves only.
- **`pnpm verify:claims` and `pnpm verify:coverage`.** The first reproduces the evidence behind every
  Implemented control and reports it grouped by control with its HIPAA, PCI-DSS and SOC 2 citation. The
  second fails CI if a row is marked Implemented without registered evidence, which makes the project's
  anti-overclaim rule enforced rather than remembered.
- **Operator probes**: `audit:verify` walks a chain and reports the first break, `audit:immutability`
  attacks the enforcement and requires each attempt to be refused, `audit:contention` fires concurrent
  appends and asserts the chain cannot fork, `smoke:slowloris` proves the request timeout with a raw
  socket.
- **Sixteen documentation pages** under [docs/](docs/README.md), plus an error catalogue every
  `problem+json` `type` URI resolves into.
- **Supply-chain gates in CI**: CodeQL, gitleaks over full history, dependency review, `pnpm audit` as a
  build-failing gate, and every GitHub Action pinned to a full commit SHA rather than a movable tag.

### Changed

- **Access tokens are nested JWTs**, signed with ES256 then encrypted (A256KW + A256GCM), replacing
  HS256. A symmetric signature means anything able to verify is also able to mint, so handing a second
  service the verification key handed it the power to forge roles for any tenant. **Breaking** for anyone
  who had integrated against the previous token format.
- **`typ` is `crbk-at+jwt`**, not `at+jwt`: RFC 9068 makes the latter an assertion of conformance to a
  profile this kit does not meet.
- **The cross-tenant check moved inside `AccessTokenGuard`**, in the same step as authentication, so it
  cannot be omitted from a guard chain. It fails closed.
- **`ioredis` 6** speaks RESP3 by default, which **raises the minimum Redis version to 6**. Pass
  `protocol: 2` for older servers, including ElastiCache on Redis 5.
- Postgres and Redis moved off their default host ports in `docker-compose.yml` (55432 and 56379), so a
  first run does not collide with an existing local instance.

### Fixed

- Three unauthenticated or unbounded paths closed, and the OpenAPI document made to describe the API as
  it actually behaves, envelope included.
- A token retry that disguised a server fault as a 401.
- Several documentation and mapping overclaims, in both directions. The pitch once named four headline
  capabilities when three did not exist; the README later understated the same work. Both are the same
  drift, and the coverage gate above exists so the next one fails a build instead of shipping.

### Known gaps

Stated because a compliance kit that hides its gaps is worse than no kit. Full list under
[Status](README.md#status); the ones most likely to matter:

- Audit appends are inline and **fail open**, so an append failure means the action happened unrecorded.
- The audit head hash is **anchored nowhere**, so a rewrite by someone with write access who recomputes
  every hash forward produces a chain that verifies.
- The **key-encrypting key is in configuration**. No KMS or HSM adapter is written; `KeyProvider` is the
  seam for one.
- **No MFA or passkeys.** Login throttling is not a substitute.
- **TLS terminates upstream.** The kit speaks plain HTTP.
- Permissions are baked into the token at login, so revocation waits for expiry.
- Existing tenant databases are never migrated; only newly provisioned ones get the current DDL.

### Verification

Every claim above is checkable on your own machine: 267 unit tests, a 92-check end-to-end suite against
real Postgres and Redis, and `pnpm verify:claims` reporting 51 evidence items across the nine Implemented
rows. CI runs all of it on every commit.
