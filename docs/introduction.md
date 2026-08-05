# Introduction

What this kit is, who it is for, and the things it deliberately does not claim.

## A controls list, not a feature list

There are many NestJS boilerplates. Most present a feature list: auth, RBAC, Docker, Swagger, a
folder structure. That tells you what code exists. It does not tell you whether the code satisfies
anything you will be asked about in an audit.

This kit is organised the other way round. Every capability maps to a **named control** in HIPAA
(45 CFR Part 164), PCI-DSS v4.0.1, or the AICPA 2017 Trust Services Criteria, and every mapping
carries a **status**: implemented, partial, not implemented, or not implemented here. That table is
[COMPLIANCE.md](../COMPLIANCE.md) and it is the centre of the project, not an appendix to it.

The difference matters most where it is least flattering. Of the sixteen rows in that table, nine
are implemented. The other seven are listed anyway, with the gap stated, because a control mapping
that lists only what you have is a marketing document.

## What you actually get

A NestJS + TypeScript monorepo that runs, with:

- **Database-per-tenant isolation**, enforced by Postgres rather than by a `WHERE tenant_id = ?`
  that someone can forget. See [multi-tenancy](multi-tenancy.md).
- **Nested JWT access tokens**, signed with ES256 then encrypted with A256KW + A256GCM, so the
  claims are unreadable without the key and a verifier cannot mint. See
  [authentication](authentication.md).
- **A key registry** in the master database holding wrapped key material, with a
  pending/active/retiring/revoked lifecycle enforced by database constraints, graceful rotation, and
  a published JWKS. See [key management](key-management.md).
- **An append-only hash-chained audit log**, one chain per tenant plus one for the control plane,
  with the append-only property enforced by Postgres triggers and a verifier that detects tampering.
  See [audit log](audit-log.md).
- **RBAC** with a permission catalogue declared in one place, so a permission that is checked but
  never granted cannot silently become a permanent 403. See [authorization](authorization.md).
- **Rate limiting and login throttling** on Redis, plus request-level denial-of-service limits.
  See [rate limiting](rate-limiting.md).
- **One response contract**: `{ success, data, meta }` for success, RFC 9457 Problem Details for
  errors. See [the response contract](responses.md).

## What it is not

**It does not make you compliant.** HIPAA, PCI-DSS and SOC 2 each require organisational policies,
workforce controls, risk assessments and formal third-party assessment: a QSA or SAQ for PCI, a
licensed CPA firm for a SOC 2 report. Deploying this kit satisfies none of those. It provides
technical scaffolding that supports some of the technical controls, which is a genuinely useful
thing and a much smaller thing than compliance.

**It is not a certification, an attestation, or legal advice.** Nobody has audited this repository
except its author.

**It is not finished.** There is no MFA or passkey support, no encryption at rest, no KMS or HSM
adapter (so the key-encrypting key still comes from configuration), and TLS terminates upstream. Each
of those is a row in the mapping with an honest status.

**It is not battle-tested at scale.** It runs, it is verified against real Postgres and Redis on
every commit, and it has never carried production traffic.

## Clean-room, and why that is stated up front

Every line is original, written from public specifications and published standards. No code is
copied or adapted from any employer or client. Where a design decision cites a reason, that reason
comes from the RFC, the eCFR text, the PCI SSC document or the vendor's own documentation, and it was
checked against the primary source rather than recalled.

This matters to you as an adopter for one practical reason: the MIT licence on this repository is
the whole licence story. There is no third-party code with other terms mixed in.

## Where to go next

If you want it running, go to [getting started](getting-started.md).

If you are evaluating whether the claims hold, go to [testing](testing.md). It lists what is proven
and how, including the probes you can run yourself against your own instance.

If you are deciding whether the architecture fits your problem,
[multi-tenancy](multi-tenancy.md) is the load-bearing decision and the one hardest to change later.
