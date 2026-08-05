# Audit log

Append-only, hash-chained, one chain per database: how it works, how to add events, and how to prove it
has not been edited.

## The design

**Every database that holds data carries its own independent hash chain.** Each tenant database has one
for that tenant's events; the master database has a separate one for control-plane events. N+1 chains,
never one central chain.

Each row links to its predecessor:

```
hash = sha256("crbk.audit.v1" || prev_hash || canonical_form(event))
```

Genesis is 32 zero bytes rather than NULL, so `UNIQUE(prev_hash)` also prevents a second first-event.

## Why per-tenant chains, not one central one

This was the open design question and it is settled. Four reasons, so it is not relitigated:

1. **Events belong where the data is.** Audit records about a tenant's users *are* that tenant's data.
   Centralising them breaks the property the whole architecture rests on, and takes per-tenant export,
   data residency and deletion with it.
2. **A central head makes the master a single point of failure for every write.** Each audited action
   would need a cross-database round trip, so a master outage would stop every tenant doing anything
   auditable. That is worse availability than the risk being managed.
3. **Postgres advisory locks are per-database.** A per-tenant chain can therefore be serialised correctly
   and cheaply with `pg_advisory_xact_lock`. A chain spanning tenants cannot be serialised with one lock
   at all, which was the original problem.
4. **The cost is no global total ordering across tenants**, and it is small. The question an assessor asks
   is "show me the events for this tenant", which per-tenant ordering answers exactly.

Control-plane events are the exception because at provisioning time the tenant database does not exist
yet, so there is nowhere else to put them.

## How an append works

One transaction, three steps, and the order is the whole thing:

```
1. pg_advisory_xact_lock(<constant>)          -- FIRST
2. SELECT now(), (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1)
3. INSERT the new row with prev_hash and the computed hash
```

**The lock is taken before the head is read, and that is not interchangeable with taking it after.**
Appending is a read-modify-write: two callers that both read head H both produce an event whose
`prev_hash` is H, and the chain forks into two histories that each verify perfectly on their own. Nothing
afterwards can tell you which is real. A lock acquired after the read protects a value that has already
been observed.

Because it is the `_xact_` variant it releases when the transaction ends, including on rollback, so a
failed append cannot leave the chain locked.

`UNIQUE(prev_hash)` is the **second line of defence** and stays there deliberately. If the lock is ever
removed, mis-keyed, or bypassed by another code path, the database refuses the second insert rather than
accepting a fork.

### The timestamp comes from the database

`now()` is read in the same round trip as the head, for two reasons. It has to be known at append time
because it is part of the hash, so a column default could not work: the value would not be chosen yet.
And taking it from the appending process would put every instance's clock into the evidence, so two
machines a second apart would write events whose recorded order contradicted their chain order, and NTP
drift on one box would silently skew a whole tenant's timeline.

`now()` is transaction start time, so it is stable between the read and the insert.

### Metadata is a flat map of strings, and that is not laziness

`jsonb` rewrites numbers (`1e2` becomes `100`) and reorders keys. A hash over anything else therefore
fails **for reasons unrelated to tampering**, and it presents as tampering: an investigator would be
handed a false positive at exactly the moment they most need to trust the tool.

So metadata values must be strings, and a database CHECK constraint enforces it rather than trusting the
caller. Nesting is refused too, because a nested object would serialise into the hash as whatever the
canonical form happened to do with it, which is a rule nobody wrote down.

### One writer, two clients

`appendAuditEvent` accepts a narrow structural interface, not a Prisma client type:

```ts
interface AuditChainClient {
  $transaction<T>(fn: (tx: AuditChainTransaction) => Promise<T>): Promise<T>;
}
```

The master and tenant clients are **separately generated types** that happen to have the same shape.
Importing one would tie the writer to that database; a cast would accept either and also accept anything
else, including the wrong client for the current tenant. An interface accepts both honestly and still
rejects an object that cannot do the job.

It uses raw SQL rather than `auditEvent.create` for the same reason: that method exists on two unrelated
types, whereas `$queryRawUnsafe` is identical on both, and the append needs `pg_advisory_xact_lock` and
server `now()` anyway.

One Prisma quirk worth knowing: the lock goes through `$executeRawUnsafe`, not `$queryRawUnsafe`, because
`pg_advisory_xact_lock` returns `void` and Prisma's query path tries to deserialize every column, failing
with "Failed to deserialize column of type 'void'".

## Append-only enforcement: three layers

All in `packages/db/sql/audit-immutability.sql`, applied to the master by its migration and to every
tenant database inside the provisioning transaction. One file used in both places, because two copies of
a security control eventually disagree and the drift is invisible until someone modifies a row and
succeeds.

1. **A row trigger on UPDATE and DELETE.** Raises `restrict_violation`. Fires for every role including
   superusers, which makes it the strongest layer in the kit's default setup, where the service and the
   migrations connect as the same privileged role.
2. **A statement trigger on TRUNCATE.** Row triggers **do not fire for TRUNCATE at all**: it deallocates
   the underlying files without visiting rows. Relying on the row trigger alone would leave
   `TRUNCATE audit_events` as a one-statement way to erase the entire log, which is exactly the operation
   someone covering their tracks reaches for.
3. **`REVOKE UPDATE, DELETE, TRUNCATE ... FROM PUBLIC`.** The layer that keeps working if a trigger is
   ever dropped. It only bites for a role that is neither the table owner nor a superuser, so **in the
   default single-role setup it is documentation of intent**. In a deployment that runs the service as a
   restricted role it becomes the real boundary.

Plus CHECK constraints that make the chain's construction rules self-enforcing: both hashes exactly 32
bytes, metadata flat strings, a non-empty action, and the actor pairing described below.

### What this does not do

**A superuser can bypass all of it.** `ALTER TABLE ... DISABLE TRIGGER ALL`, or
`SET session_replication_role = 'replica'`, or simply `DROP TRIGGER`. So this is enforcement against the
application, against an ordinary compromise of the service, and against an operator's mistake. It is
**not** enforcement against someone holding superuser.

Two things close that gap and neither belongs in the SQL: restrict who holds superuser, and **ship the
head hash off the box** so a rewrite that succeeds locally still fails to match the value recorded
elsewhere.

The honest claim is "append-only as enforced against the application role, and tamper-evident beyond
that". Not "immutable".

### What the chain cannot detect

Two limits, both stated in the code and worth knowing before you rely on this.

**A full tail rewrite.** If someone can edit rows *and* recompute every hash from their edit forward, the
result is a chain that verifies perfectly. Comparing the head against a value stored somewhere the
database cannot reach is what closes that, and nothing inside the database can. `pnpm audit:verify` prints
the head hash for exactly this purpose. **The kit does not anchor it anywhere**; that is on you and it is
a real gap.

**A missing event.** A chain over events 1..n verifies whether or not something that was never written
belonged between them. This matters because appends fail open; see below.

## Emitting an event

Inject `AuditService` and call one of two methods:

```ts
constructor(private readonly audit: AuditService) {}

// Goes to the CURRENT TENANT's chain. Only valid in a request that resolved a tenant.
await this.audit.tenantEvent({
  action: "user.registered",
  actorType: "user",
  actorId: user.id,
  resourceType: "user",
  resourceId: user.id,
  sourceIp: req.ip,
  metadata: { email: normalisedEmail },   // strings only
});

// Goes to the deployment-wide control-plane chain.
await this.audit.controlPlaneEvent({
  action: "tenant.provisioned",
  actorType: "control_plane",
  actorId: null,
  metadata: { slug, databaseName },
});
```

Events the kit emits today: `tenant.provisioned` (master chain), login succeeded, failed and throttled,
user registered, and `authz.denied`.

### Appends fail open, loudly

This is the decision most worth arguing with, so here is the reasoning.

A failed append is logged at **error** level and the request proceeds. Failing the request instead is
defensible and stricter, and it is wrong here: it makes the audit chain a hard dependency for logging in,
so an unreachable tenant database would lock every user out of an otherwise healthy service, and a
provisioning failure after the database was created would leave an orphaned tenant. Turning an
evidence-recording problem into an availability outage is a bad trade in both directions.

What that costs, stated rather than buried: **during an append failure the service performs actions it
does not record, and the hash chain cannot reveal that gap.** Detecting absence needs something the chain
does not provide.

So every failure logs at error level with every field needed to reconstruct the lost event, because that
log line is the only remaining record that the action happened. And a deployment that must not lose events
should write ahead to a durable queue and drain it into the chain rather than appending inline as this
does.

### What the control-plane chain cannot tell you

`tenant.provisioned` records actor type `control_plane` and **no actor id**, and the
`audit_events_actor_ck` constraint enforces that rather than trusting the caller.

The reason is honesty. The control-plane credential is a shared secret that authenticates the *bearer*,
not a person, so any identifier written there would imply an attribution the credential cannot support.
An audit trail that implies attribution it does not have is worse than one that admits the gap.

If you need operator attribution, replace the shared secret with mutual TLS or a signed operator token
carrying an identity. See [configuration](configuration.md#the-two-256-bit-keys).

## Verifying a chain

```bash
pnpm audit:verify --master              # the control-plane chain
pnpm audit:verify --tenant acme         # one tenant's chain
pnpm audit:verify --tenant acme --page-size 5000
```

Walks in pages, recomputing every hash from what the database returned and checking each link against its
predecessor. Reports the first break with its `seq`, or:

```
OK: 194 event(s), chain intact from genesis to head.
head hash: ce7d769c...
Record that head hash somewhere this database cannot reach.
```

An **empty** chain reports `EMPTY`, not `OK`. A chain that verifies while recording nothing is the failure
mode worth catching, and the smoke test asserts specifically that the chain is not empty after the suite
has provoked events.

You must specify exactly one of `--master` or `--tenant`, rather than defaulting, because "verify passed"
against the wrong database is the most misleading output the tool could produce.

## Proving the enforcement, not just the chain

Two probes, each covering something the other structurally cannot.

```bash
pnpm audit:immutability --master         # or --tenant <slug|uuid>
```

Attempts UPDATE, DELETE and TRUNCATE, plus a duplicate `prev_hash`, and requires each to be refused with
the right SQLSTATE. Then confirms the chain is unchanged, and that a normal append still works, so a table
that refused *everything* cannot pass.

**Every destructive attempt runs inside a transaction that is rolled back.** If a trigger has been
dropped, `TRUNCATE audit_events` is precisely the erasure the trigger exists to prevent, and a probe that
executed it would destroy the evidence it was asked to check, in the situation where that evidence matters
most. TRUNCATE is transactional in Postgres, so a ROLLBACK genuinely undoes it.

It **refuses to run against an empty chain**, because `UPDATE` and `DELETE` triggers are per-row and never
fire when nothing matches: both checks would pass against a table with no protection at all.

```bash
pnpm audit:contention --appends 50
```

Fires concurrent appends and asserts `UNIQUE(prev_hash)` **never** fires. That is the pass condition, not
merely "no errors": a run where appends hit the unique constraint and retried would look healthy while
proving the opposite, that the lock did not serialise and the database caught what the application should
have prevented.

Both are run in CI on every commit.

## Control mapping

Append-only audit logging maps to HIPAA 164.312(b) and 164.308(a)(1)(ii)(D), PCI-DSS Req 10 (10.2,
10.3.2), and SOC 2 CC7.2, marked **Implemented**, with the superuser caveat above stated in
COMPLIANCE.md itself.

Note what is still missing for a full Req 10 story: there is no log retention policy, no off-box shipping,
no external anchoring of the head hash, and no OpenTelemetry export. The structured-logging row is
**Partial** for those reasons. See [COMPLIANCE.md](../COMPLIANCE.md).
