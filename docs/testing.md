# Testing

What is proven, how, and the deliberate decision not to unit test the database layers.

## The suites

| Command | What it is | Needs |
| --- | --- | --- |
| `pnpm test` | 248 unit tests across 15 files | nothing |
| `pnpm smoke` | 92 end-to-end checks | a running service, Postgres, Redis |
| `pnpm smoke:slowloris` | raw-socket request-timeout probe | a running service |
| `pnpm audit:contention` | concurrent-append fork probe | Postgres |
| `pnpm audit:immutability --master \| --tenant <slug\|uuid>` | append-only enforcement probe | Postgres |
| `pnpm audit:verify --master \| --tenant <slug\|uuid>` | walks a chain and reports the first break | Postgres |
| `pnpm verify:claims` | all of the above, reported per compliance control | everything |
| `pnpm verify:coverage` | static evidence-coverage gate | nothing |

CI runs every one of them on every commit, in two jobs: one that needs no database (lint, format, unit
tests with coverage, the coverage gate) and one that runs against real Postgres and Redis service
containers. The database-backed job additionally exercises key rotation and revocation, which is not unit
tested for the reasons below.

## Reading the results by control instead of by suite

The table above is organised by mechanism, which is the wrong axis for the question most readers of this
repository actually have. "248 tests pass" is a fact about the project's diligence; it is not an answer to
"is multi-tenant isolation real". `pnpm verify:claims` runs the same suites and reports every result
grouped under the control it supports, with that control's HIPAA, PCI-DSS and SOC 2 citation beside it:
51 items across the nine rows COMPLIANCE.md marks Implemented, plus one on a Partial row.

It re-implements nothing. Each entry in its registry is a substring matched against a **passing line** of
a suite's real output, so the assertions stay where they were written. A copy of an assertion inside that
script would be a second source of truth able to keep printing PASS after the original had changed, which
is the one failure a compliance document cannot survive. A match that resolves nowhere is reported as
MISSING rather than FAIL, because "the evidence was renamed" and "the control broke" are different
problems and one exit code for both would hide each behind the other.

`pnpm verify:coverage` is the half CI can run on every pull request, since it reads markdown and executes
nothing: it **fails the build** if a row marked Implemented has no registered evidence, or if the registry
names a row COMPLIANCE.md no longer contains. That makes the project's anti-overclaim rule enforced rather
than remembered. Per the rule in the next section, it was checked by breaking it: flipping a
Not-implemented row to Implemented fails, and renaming a row reports both halves of the problem at once.

The immutability probe runs there against **both** chains, the master and one of the tenants the smoke
suite provisions. Both, because the enforcement reaches them by different routes and either can regress
alone: the master gets `packages/db/sql/audit-immutability.sql` inlined into its migration, while a
tenant database gets it applied inside the provisioning transaction. A tenant whose provisioning skipped
it would leave the master passing and every customer's log unprotected.

## The rule these suites are built around

**A test that cannot fail is worse than no test, because it is trusted.**

That sounds obvious and it has been violated repeatedly in this repository, which is why it is written
down. Every instance below is real:

- The **slowloris probe** originally passed on *any* quick response, so it would have passed against a
  server with no timeout at all. It now asserts a 408 at roughly the configured deadline.
- The **contention probe** shipped twice with a vacuous pass. Once when every append failed: no rows came
  back, the verification loops never ran, and both checks printed PASS. Once when `--appends abc` made
  `Number()` return NaN, `Array.from({length: NaN})` produced an empty array, and it announced "Firing NaN
  concurrent appends" before passing everything.
- The **immutability probe** would pass against a completely unprotected table if the chain were empty,
  because UPDATE and DELETE triggers are per-row and never fire when nothing matches. It refuses to run on
  an empty chain for that reason.
- The **rate limiter's** atomicity claim is proven by implementing the *naive* GET-then-SET limiter inside
  the test and asserting that it over-admits. Without that, a passing test of the real limiter would not
  show the Lua script was doing anything.
- **Smoke step 0** was verified non-vacuous by setting `SMOKE_MAX_UPTIME=1` and confirming it fails.

So when you add a check here, the expected work is not just "does it pass" but "did I watch it fail for the
right reason". For the immutability probe that meant building a scratch database with the table DDL and
*without* the immutability SQL, and confirming all three trigger assertions failed while the rollback
safety net still protected the log.

That exercise also demoted one of its own assertions. The `REVOKE` check passed in the scratch database
where the REVOKE had never run, because Postgres grants PUBLIC no table privileges by default. Its message
now says it detects a stray `GRANT` rather than claiming to confirm the REVOKE, which is all it can
honestly do.

## Unit tests

15 spec files, all colocated with their subject:

```
packages/config/src/index.spec.ts               config schema, key separation, boot invariants
packages/crypto/src/audit-hash.spec.ts          canonical form, chain verification, tamper detection
packages/crypto/src/key-material.spec.ts        key generation, JWK export
packages/crypto/src/key-provider.spec.ts        envelope wrap/unwrap, AAD binding
packages/crypto/src/passwords.spec.ts           Argon2id, rehash detection, decoy verification
packages/crypto/src/tokens.spec.ts              nested JWT issue and verify, forgery rejection
services/auth/src/audit/audit.service.spec.ts   chain selection, fail-open behaviour
services/auth/src/auth/login-throttle.service.spec.ts
services/auth/src/auth/token.service.spec.ts
services/auth/src/common/problem-details.filter.spec.ts
services/auth/src/common/validation-exception.factory.spec.ts
services/auth/src/keys/key-registry.service.spec.ts
services/auth/src/ratelimit/rate-limit.store.spec.ts
services/auth/src/rbac/permissions.guard.spec.ts
services/auth/src/tenants/control-plane.guard.spec.ts
```

Unit tests alias workspace imports to **source** rather than `dist`, so they run without a build.

## Why the database layers have no unit tests

The `ConnectionManager`, the tenant services and the operator CLIs have **no unit tests**, deliberately.
The reason is recorded in `vitest.config.ts` and it is not laziness.

What makes those layers correct lives in **database semantics**, and a mock would only assert my beliefs
about those semantics. Consider what a mocked test of the audit writer could establish: that
`pg_advisory_xact_lock` is called before the head is read. That is worth something. What it cannot
establish is whether the lock actually serialises anything, which depends on Postgres, on every caller
using the same key, and on the read and the insert sharing one transaction. Only real contention settles
it, which is why `pnpm audit:contention` exists instead.

The same argument applies to key rotation. What makes it correct is the partial unique index permitting one
active key per purpose, and the single transaction that retires the old key while promoting the new one. A
fake ConnectionManager would assert my beliefs about those constraints rather than the constraints. So
`manage-keys.ts` is excluded from coverage and exercised against real Postgres in CI, including asserting
that revoking the **active** key is refused.

The consequence is a modest overall line coverage of around 50%. **The per-glob thresholds are the real
gate**, not the total: `packages/crypto` requires 100% lines and functions, the token codec requires 100%
lines with 80% branches, and the aggregate floor is 45%. A single number across a repository where half the
code is only meaningfully testable against a live database would be a misleading target.

Module files, `main.ts` and DTOs are excluded: declarative wiring with no branches, covered by the smoke
test actually booting the application.

## The smoke test

92 checks in 18 steps against a running service. Notable ones:

| Step | Proves |
| --- | --- |
| 0 | You are talking to the server you just built |
| 1 | The control plane refuses callers without its credential, **and the limiter runs before authentication** |
| 3 | Provisioning creates no users |
| 5, 6 | The token's claims are unreadable without the key, and its verified claims carry tenant, user, roles, permissions |
| 7 to 9 | RBAC allows the seeded admin and denies a fresh registration |
| 10 | Wrong password and unknown user fail **identically** |
| 11 | Two tenants cannot see each other's users (isolation) |
| 12 | A token for one tenant is refused by another (authorization) |
| 13 | Forged, unencrypted and tampered tokens are all refused |
| 15 | Every response follows the contract |
| 16 | The published JWKS carries only public halves |
| 17 | The OpenAPI document matches actual behaviour |
| 18 | The audit log recorded what the suite did, and both chains verify from genesis |

### Step 0 exists because of a real incident

A `nest start --watch` left over from an earlier test kept `:3011`, the freshly built server failed to bind
with `EADDRINUSE`, and **64 checks passed against the wrong process.** Step 0 now checks the reported
version against `services/auth/package.json`, requires uptime below `SMOKE_MAX_UPTIME` (1800s default), and
requires that exactly one process holds the port.

This is also why CI polls `/api/health` rather than grepping the log for "listening on". A log line means a
message was printed; a 200 means connections are actually being accepted.

### Step 13 is the one worth reading

Four separate forgery attempts, because "the token is verified" is easy to claim and easy to get wrong:

1. A **valid JWE wrapping a forged inner JWS**. This is the RFC 8725 §2.3 case: it decrypts successfully, so
   anything that treats `compactDecrypt` as verification accepts it.
2. **Per-segment tampering** of the compact serialisation.
3. An **unencrypted but correctly signed** token, so a JWS is not accepted where a nested JWT is required.
4. An **unknown `kid`**, which must produce a clean 401 rather than a 500 from a database error.

### `CONTROL_PLANE_API_KEY` must be exported

The smoke script reads it from the **shell environment**, not from `.env`, because CI has no `.env` and
under `set -e` an unset variable would abort the whole run rather than fail one check. Forget the export and
about a dozen checks fail with `CONTROL_PLANE_UNAUTHORIZED`, which looks like a broken install.

## What each separate probe covers

**`pnpm smoke:slowloris`** needs a raw socket, so it cannot live in an HTTP test suite. It reproduces the
dribbled-body attack: complete the headers, declare a `Content-Length`, then send the body one byte at a
time. No inactivity timeout fires, so nothing but `requestTimeout` bounds it. The probe asserts a **408 at
roughly the configured deadline**, not merely any response that arrives in time.

CI runs it with `REQUEST_TIMEOUT_MS=4000` so the job does not wait 30 seconds. That is not a weakened test:
the mechanism is what it proves, and the 30s production default is asserted by the config unit tests. The
service is restarted for it because the timeout is fixed at construction, and CI then re-checks uptime to
confirm it is talking to the restart.

**`pnpm audit:contention`** needs concurrency, which the smoke test has none of: it drives one request at a
time, so it could prove the audit writer works and nothing about whether the advisory lock serialises
competing appends. The pass condition is that `UNIQUE(prev_hash)` **never** fires.

It asserts *at least* the expected number of rows rather than an exact count, because CI runs it with the
auth service still up, and any request emitting an audit event would otherwise fail a probe that is proving
something else entirely.

**`pnpm audit:immutability`** attempts the mutations the log must refuse. Every attempt is wrapped in a
transaction that is rolled back, so if a trigger has been dropped the probe *reports* it instead of
demonstrating it by erasing the log.

## Known gaps

- **No tests for the layers that talk to Postgres**, as argued above. Exercised for real in CI instead.
- **No load or performance testing.** Nothing establishes what throughput the kit sustains.
- **No fuzzing** of the token parser or the DTOs.
- **No multi-instance testing.** Key rotation and rate limiting both have behaviour that only appears with
  two or more processes, and CI runs one.
- **`pnpm smoke` leaves real `tenant_smoke_*` databases behind.** `pnpm clean:test-tenants` removes them.
- **No mutation testing**, which is the systematic version of the non-vacuity checking done by hand above.
