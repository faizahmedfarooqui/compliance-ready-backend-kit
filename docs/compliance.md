# Compliance mapping

How to read [COMPLIANCE.md](../COMPLIANCE.md), what the statuses mean, and what this kit does not claim.

## Read the Status column first

[COMPLIANCE.md](../COMPLIANCE.md) maps sixteen capabilities to named controls in HIPAA (45 CFR Part 164),
PCI-DSS v4.0.1 and the AICPA 2017 Trust Services Criteria. **Nine are implemented.** Three are partial, two
are not implemented, and two are deliberately outside this repository.

The table maps capabilities to controls; it does **not** assert that this repository implements all of
them. Treat any row that does not say "Implemented" as a control you still have to provide some other way.

An earlier version of that file listed thirteen rows with no status column, which read as a claim to all
thirteen. That is the failure mode the Status column exists to prevent, and it is worth knowing about
because it is the normal way this kind of document goes wrong: nobody writes a false claim on purpose, they
just list the controls they were thinking about.

### What each status means

| Status | Means |
| --- | --- |
| **Implemented** | Realised in this repository and exercised by the automated tests. You still own the organisational half |
| **Partial** | Some of it exists. The row's note says exactly which part, and which part does not |
| **Not implemented** | The row exists because the control is on the roadmap, not because the code provides it. **Do not cite these as evidence of anything** |
| **Not implemented here** | A real and mandatory control, satisfied outside this repository or not at all. TLS is the example |

"Partial" is the status that needs the most care. Key management has envelope encryption, a `kid`-indexed
registry with a database-enforced lifecycle, graceful rotation and a published JWKS. What it does **not**
have is a KMS or HSM adapter, so the key-encrypting key still comes from configuration. That means the row
should not be cited against a requirement calling for a secure cryptographic device, even though most of
the row is real. See [key management](key-management.md#what-is-not-done-yet).

## What the kit does not claim

**It does not make you compliant, and it is not a certification.** HIPAA, PCI-DSS and SOC 2 each require
organisational policies, workforce controls, risk assessments and formal third-party assessment: a QSA and
ROC or an SAQ for PCI, a licensed CPA firm for a SOC 2 report, OCR enforcement or self-attestation for
HIPAA. Deploying this kit satisfies none of those.

What it provides is technical scaffolding for some of the **technical** controls. That is genuinely useful
and much smaller than compliance.

**Nobody has audited this repository except its author.**

## Caveats that are easy to get wrong

These are in COMPLIANCE.md and worth repeating, because each one is a place where people over-read a
mapping.

**"Addressable" does not mean optional.** Several HIPAA Security Rule requirements are labelled
addressable rather than required. That means you may implement an equivalent alternative measure *and
document why*, not that you may skip it.

**PCI-DSS applies only inside the cardholder data environment.** If this service never touches cardholder
data, the PCI column is not a requirement you inherit. Scoping is the first question a QSA asks.

**SOC 2 criteria are not a checklist.** The Trust Services Criteria describe objectives; a control is
evaluated on whether it meets the objective in your environment, which a code repository cannot determine.

**Some rows have no HIPAA mapping on purpose.** Rate limiting and DoS protection are marked "(none, see
notes)" rather than being stretched onto a technical safeguard that does not cover them. HIPAA handles
availability through the contingency-planning administrative safeguards. Inventing a citation to fill a
cell is how a mapping stops being trustworthy.

**Where a citation is uncertain, the table says so.** Several PCI references carry "unverified". That is a
deliberate admission that the mapping is the author's reading rather than a QSA's.

## Verifying the claims yourself

The point of a controls list is that someone can check it, so there is one command that does:

```bash
pnpm verify:claims
```

It runs the real suites and reports every result grouped by the control it supports, with that
control's HIPAA, PCI-DSS and SOC 2 citation next to it. Currently **51 items across the nine
Implemented rows**, plus one more on a Partial row: `pnpm audit` under vulnerability management,
which is included because the part of that row which does exist is runnable, and excluded from the
Implemented count because the row is not Implemented.

It re-implements nothing: each assertion belongs to `pnpm smoke`, the two audit probes, the
slowloris probe, the unit suite or `pnpm audit`, and this command runs those and attributes the
output. A copy of an assertion here would be a second source of truth that could drift from the real
one while still printing PASS.

It needs what those suites need: Postgres and Redis up, the service running, and
`CONTROL_PLANE_API_KEY` exported in the shell. Run `pnpm verify:claims --list` to see the registry
without executing anything.

There is also a static half, which CI runs on every pull request:

```bash
pnpm verify:coverage
```

That one reads this repository's `COMPLIANCE.md` and **fails the build if a row marked Implemented
has no registered evidence**, or if the registry names a row the document no longer contains. It is
the anti-overclaim rule enforced rather than remembered: marking a row Implemented without wiring up
the proof is now a red build rather than an oversight nobody catches.

The underlying evidence, per row:

| Row | Verify with |
| --- | --- |
| Multi-tenant isolation | `pnpm smoke` step 11 |
| RBAC / access control | `pnpm smoke` steps 7 to 9 |
| Password storage (Argon2id) | `pnpm test` (`passwords.spec.ts`) |
| Access-token confidentiality | `pnpm smoke` steps 5, 6, 13 |
| Input validation | `pnpm smoke` step 15 |
| Append-only audit logging | `pnpm audit:immutability`, `pnpm audit:verify`, `pnpm audit:contention`, `pnpm smoke` step 18 |
| Rate limiting and login throttling | `pnpm smoke` step 1, `pnpm test` (`rate-limit.store.spec.ts`) |
| Request-level DoS limits | `pnpm smoke:slowloris` |
| Control-plane authorization | `pnpm smoke` step 1 |

See [testing](testing.md) for what each one actually establishes, and for the standard those checks are
held to: a test that cannot fail is worse than no test. That standard applies to the coverage gate
too, which is why it was checked by flipping a row to Implemented and confirming the build went red,
rather than by observing that it passed.

## If a doc and COMPLIANCE.md disagree

**COMPLIANCE.md's Status column wins**, and the page is a bug. Please report it.

The same rule governs the project's own README and pitch. An earlier README pitched "passkeys,
Postgres-enforced tenant isolation, KMS envelope encryption, and append-only audit logs" when three of
those four did not exist. Copy that states intentions as facts is how an overclaim happens by accident, and
it propagates: every later document and commit message inherits it.

So when adding a headline capability to any description of this kit, check the Status column first.

## Related pages

- [Introduction](introduction.md) for what the kit is and is not.
- [Testing](testing.md) for how each claim is proven.
- [Audit log](audit-log.md#what-this-does-not-do) for the clearest worked example of a control stated with
  its limits: append-only against the application role, tamper-evident beyond that, and not immutable
  against a superuser.
