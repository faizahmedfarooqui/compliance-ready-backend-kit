# Compliance control mapping

This document maps each capability the kit provides to the specific control it helps
satisfy in **HIPAA** (Security Rule, 45 CFR Part 164), **PCI-DSS v4.0.1**, and
**SOC 2** (AICPA 2017 Trust Services Criteria). It is the core of the project: a
controls list, not a feature list.

> **Read this first.** The kit provides technical *scaffolding and control
> implementations*. It does **not** make you compliant or certified. HIPAA, PCI-DSS,
> and SOC 2 each also require organizational policies, workforce controls, risk
> assessments, and formal third-party assessment (a QSA/ROC or SAQ for PCI, a licensed
> CPA firm for a SOC 2 report, OCR enforcement or self-attestation for HIPAA).
> Deploying this kit does not, by itself, satisfy any of them.

## Control mapping

**Read the Status column before anything else.** This table maps capabilities to controls; it
does not assert that this repository implements all of them. Of the sixteen rows, **nine** are
implemented, **three** are partial, **two** are not implemented at all, and **two** are
deliberately outside this repository. An earlier version of this file listed thirteen rows with no
status column, which read as a claim to all of them. Treat any row that does not say "Implemented"
as a control you still have to provide some other way.

| Capability | Status | HIPAA (45 CFR) | PCI-DSS v4.0.1 | SOC 2 (TSC) |
| --- | --- | --- | --- | --- |
| Multi-tenant isolation (database-per-tenant) | **Implemented** | 164.312(a)(1) | Req 7 | CC6.1 |
| RBAC / access control | **Implemented** | 164.312(a)(1); 164.312(a)(2)(i); 164.308(a)(4) | Req 7 | CC6.3 |
| Password storage (Argon2id KDF) | **Implemented** | 164.312(d) | Req 8 (8.3.2) | CC6.1 |
| Access-token confidentiality (nested JWT: signed, then encrypted) | **Implemented** | 164.308(a)(1)(ii)(B) | Req 6 (6.2.4); Req 12 (12.3.3) | CC6.1 |
| Input validation | **Implemented** | 164.312(c)(1) | Req 6 (6.2.4) | CC8.1 |
| Vulnerability / dependency management | Partial | 164.308(a)(8); 164.308(a)(5)(ii)(B) | Req 6 (6.3.1-6.3.3); Req 11 (11.3) | CC7.1 |
| Structured logging + monitoring (OpenTelemetry) | Partial | 164.312(b); 164.308(a)(1)(ii)(D) | Req 10 | CC7.2 |
| Append-only audit logging (hash-chained) | **Implemented** | 164.312(b); 164.308(a)(1)(ii)(D) | Req 10 (10.2, 10.3.2) | CC7.2 |
| Authentication (MFA / passkeys / WebAuthn) | **Not implemented** | 164.312(d) | Req 8 (8.4, 8.5) | CC6.1 |
| Key management (envelope encryption, rotation, JWKS) | Partial | 164.312(a)(2)(iv) | Req 3 (3.6, 3.7, unverified) | CC6.1 |
| Encryption at rest | **Not implemented** | 164.312(a)(2)(iv) | Req 3 (3.5, 3.5.1) | CC6.1 |
| Encryption in transit (TLS) | **Not implemented here** | 164.312(e)(1); 164.312(e)(2)(ii) | Req 4 (4.2.1) | CC6.7 |
| Rate limiting and login throttling (application layer) | **Implemented** | (none, see notes) | Req 8 (8.3.4, unverified) | CC6.6 |
| DoS / DDoS protection (network layer) | **Not implemented here** | (none, see notes) | Req 6 (6.4.2, unverified) | CC6.6 |
| Request-level DoS limits (timeouts, body size) | **Implemented** | (none, see notes) | (none, see notes) | CC6.6 |
| Control-plane authorization (tenant provisioning) | **Implemented** | 164.312(a)(1); 164.308(a)(4) | Req 7 | CC6.3 |

### What the statuses mean

- **Implemented** — the control is realised in this repository and exercised by the automated
  tests. You still own the organisational half of it.
- **Partial** — some of it exists. Key management has envelope encryption, a `kid`-indexed registry
  with a pending/active/retiring/revoked lifecycle enforced by database constraints, graceful
  rotation with an overlap, and a published JWKS. What it does **not** have is a KMS or HSM adapter:
  the key-encrypting key still comes from configuration, so it is only as protected as the process
  and its config store. The `KeyProvider` port exists so that substitution is a new file rather than
  a redesign, but until it is written, do not cite this row against a requirement that calls for a
  secure cryptographic device. Dependency management now has a committed lockfile, Dependabot,
  CodeQL, gitleaks over full history, dependency review on pull requests, every GitHub Action pinned
  to a full commit SHA rather than a movable tag, and `pnpm audit` as a build-failing gate; what is
  still missing is an SBOM and a documented 12-month cryptographic inventory review (PCI 12.3.3).
  Note also that the branch ruleset does not currently require status checks to pass before merging,
  so these gates are enforced by convention at the merge button rather than by the platform. Logging is structured through the
  framework logger and carries a trace id on every error, but there is no OpenTelemetry export,
  no trace propagation and no retention policy.
- **Not implemented** — the row exists because the control is in scope for the kit's roadmap, not
  because the code provides it. Do not cite these rows as evidence of anything.
- **Not implemented here** — TLS is a real and mandatory control, but this kit terminates plain
  HTTP and assumes a load balancer or service mesh in front. That is a legitimate architecture,
  and it means the control is satisfied outside this repository or not at all.

## Notes on the mappings

- **Append-only audit logging.** A hash-chained log in every database that holds data: one chain per
  tenant, plus a separate one in the master for control-plane events. Not one central chain, because a
  shared chain would need a cross-database round trip on every audited write and could not be
  serialised anyway, since Postgres advisory locks are per-database.

  **The precise claim, because "immutable" would be an overclaim.** What is true is: *append-only as
  enforced against the application role, and tamper-evident beyond that.* Three enforcement layers, all
  verified by attempting to violate them rather than by inspection: row triggers refusing UPDATE and
  DELETE, a statement trigger refusing TRUNCATE (row triggers do not fire for TRUNCATE at all, which
  would otherwise leave one statement able to erase the log), and REVOKE of those privileges. Four CHECK
  constraints pin the hash widths, the metadata shape, a non-empty action, and the actor pairing.
  `UNIQUE(prev_hash)` makes a forked chain impossible rather than unlikely.

  **What it does NOT do.** A superuser can drop or disable a trigger, or set
  `session_replication_role`. So this is enforcement against the application, against an ordinary
  compromise of the service, and against operator error, not against someone holding superuser on the
  database. Beyond that point the hash chain makes an edit DETECTABLE rather than impossible, and even
  that has a limit: an attacker who can write to the table and recompute every hash from their edit to
  the head produces a chain that verifies. Closing that needs the head hash recorded somewhere the
  database cannot reach, which `pnpm audit:verify` prints for exactly that purpose, and which this kit
  does not automate.

  **A chain nobody walks is a column of hashes**, so `pnpm audit:verify --master` or
  `--tenant <slug>` walks it in pages and reports the first break, distinguishing an altered field from
  a removed event from a truncated start. Verified by tampering: each of those three cases is planted
  and detected, and restoring the original value returns the chain to intact, so the detection is not
  merely always-failing.

  **What is recorded**: tenant provisioned (master chain), login succeeded, failed and throttled, user
  registered, and authorization denied. A failed login uses ONE action name for "no such user" and
  "disabled account", matching the response, so the log does not answer the account-enumeration question
  the API refuses to answer; the reason sits in metadata instead.

  **Two honest gaps.** Appends are inline and fail OPEN: a failed append is logged at error level and the
  request proceeds, because making the chain a hard dependency for logging in would turn an unreachable
  database into a total authentication outage. The chain cannot reveal an event that was never written,
  so a deployment that must not lose events should write ahead to a durable queue. And a control-plane
  event records that the control plane was used, not by whom, because the credential authenticates the
  bearer rather than a person; PCI Req 10.2 asks for user identification, and this kit cannot supply it
  for control-plane actions until mutual TLS or a signed operator token lands.

- **Rate limiting and login throttling.** Two distinct controls, both on Redis with a sliding window
  evaluated atomically in a Lua script. A per-client request budget applies to every route, with
  stricter budgets on the routes that cost real work (`/auth/login`, `/auth/register`,
  `POST /tenants`). Login throttling counts FAILED logins per account and per source address; the
  account counter is cleared on a successful login, the address counter is not, because otherwise
  anyone holding one valid account could reset their own address budget on demand.

  On PCI-DSS 8.3.4, stated carefully: the requirement text has **not** been verified against the
  standard, hence "unverified" in the table, and a strict reading asks for a lockout of at least 30
  minutes. The kit implements a **throttle** with a configurable window, not a lockout, because an
  unauthenticated way to disable a named user indefinitely is a denial of service anyone can aim at
  anyone. Set `LOGIN_THROTTLE_WINDOW_MS=1800000` for the 30-minute reading.

  What this does **not** do: it is per-instance-shared-through-Redis, so it bounds requests, not
  bandwidth, and it cannot stop traffic before it reaches the application. Anything volumetric belongs
  in the row below.

- **Request-level DoS limits.** `requestTimeout`, `connectionTimeout`, `keepAliveTimeout` and
  `bodyLimit` are declared explicitly in validated config rather than inherited from Fastify. The one
  that matters is the request timeout, and it is worth knowing why it is not simply "an option we set":
  Fastify defaults `requestTimeout` to 0 and assigns it to the Node server unconditionally, so the
  default does not fall back to Node's 300s, it DISABLES the timeout. A client could complete its
  headers, declare a Content-Length, and then send the body one byte at a time indefinitely.

  Node also derives `headersTimeout = min(60000, requestTimeout)` inside `http.createServer` and
  validates the pair only there, so setting `requestTimeout` after construction, which is what Fastify
  does, leaves an inconsistent pair that silently never expires anything. The kit therefore passes the
  value through `http` (the constructor) AND at the top level, and `scripts/slowloris-probe.mjs`
  reproduces the attack against a real socket to prove the response is a 408.

- **Control-plane authorization.** `POST /api/tenants` creates a database. It was unauthenticated
  until v0.2, guarded by nothing but a source comment. It now requires
  `Authorization: Bearer <CONTROL_PLANE_API_KEY>`, compared in constant time after an explicit length
  check, so a wrong-length credential is a 401 rather than the crash `timingSafeEqual` would raise.

  Honest limitation, and it matters for an access-review question: this authenticates the **bearer**,
  not a person. It cannot say WHICH operator provisioned a tenant, cannot be scoped to one action, and
  rotating it invalidates every caller at once. Sufficient to close the hole, insufficient for
  attributable administrative access, which needs mutual TLS or a signed operator token carrying an
  identity.

- **Audit logging.** PCI 10.3.2 (protect audit logs from modification) is the direct
  analogue of append-only immutability. HIPAA 164.308(a)(1)(ii)(D) activity review is
  Required. SOC 2 CC7.2 covers monitoring components for anomalies.
- **Encryption at rest / in transit.** Both HIPAA specs here, 164.312(a)(2)(iv) and
  164.312(e)(2)(ii), are **Addressable** (implement, or document why not and adopt an
  equivalent). Addressable does not mean optional. PCI 3.5 is the parent standard; the
  specific "render stored PAN unreadable" obligation is 3.5.1.
- **Key management.** No HIPAA safeguard names key management; it sits under the encryption
  mechanism (Addressable). PCI is the strongest fit, 3.6 (key-management processes) and 3.7 (key
  lifecycle), though **both clause numbers are unverified here** because the standard is behind
  registration. What exists: envelope encryption, so the registry stores only wrapped material and
  the key-encrypting key never enters the tenant or master data; a `kid`-indexed lifecycle whose
  invariants are database constraints rather than application code; rotation with an overlap so a
  retiring key keeps verifying for the token TTL; and a published JWKS so a verifier needs only a
  public key. What does not exist is a secure cryptographic device holding the KEK.
- **Authentication.** PCI 8.4/8.5 mandate MFA into the CDE; some sub-requirements became
  mandatory 31 Mar 2025. Phishing-resistant passkeys exceed the baseline.
- **Password storage.** PCI 8.3.2 is the direct control (strong cryptography renders all
  authentication factors unreadable in storage and transmission). HIPAA names no
  password-storage safeguard, so 164.312(d) is the nearest standard rather than an exact
  match. The kit's Argon2id cost parameters are declared in one file and should be re-tuned
  on your own hardware.
- **Access-token confidentiality.** This row is **defence in depth, and is deliberately not
  mapped to any encryption mandate.** Read the caveat below before citing it.

  Encrypting the token payload mitigates one specific, real threat: disclosure of the claims
  to the party holding the token, which includes the browser it was issued to and the end
  user. RFC 9068 §6 states it plainly: "it now becomes possible for clients and potentially
  even end users to directly peek inside the token claims collection of unencrypted tokens",
  and lists encrypting the token among the remedies. In this kit the claims include the
  tenant id, user id, and the full set of roles and permissions the principal holds.

  It does **not** mitigate a network attacker, because TLS already does. Both RFC 7519 §12 and
  RFC 8725 (BCP 225) §3.2 treat transport encryption and an encrypted JWT as alternative ways
  of satisfying the same requirement, §3.2 saying that with a current transport layer "there
  may be no need to apply another layer of cryptographic protections to the JWT". So the
  honest HIPAA hook is the Required **risk management** specification, 164.308(a)(1)(ii)(B)
  ("Implement security measures sufficient to reduce risks and vulnerabilities to a
  reasonable and appropriate level"), which is what a documented, risk-based decision to add a
  second layer actually satisfies.

  Specifically **not** claimed, and why:
  - **Not** HIPAA 164.312(a)(2)(iv) or 164.312(e)(2)(ii). Both are scoped to ePHI. Under
    45 CFR 160.103, information is ePHI only if it relates to health, care, or payment for
    care *and* identifies the individual. Opaque uuids, role names, and permission keys are
    neither. Claiming these would be exactly the overclaim this document forbids.
  - **Not** PCI 8.3.2. That row above already uses it for password storage, and Requirement 8
    defines an authentication factor as something you know, have, or are. A bearer token
    issued *after* authentication is not one; the string "session token" does not appear in
    PCI-DSS v4.0.1 at all.
  - **Not** PCI 4.2.1 or Requirement 3, both textually scoped to PAN and stored account data.
  - **Not** SOC 2 CC6.7. Its point of focus accepts "encryption technologies **or** secured
    communication channels", so TLS already discharges it and this adds nothing there. CC6.1
    is the fit, because its points of focus cover using encryption "to supplement other
    measures ... based on assessed risk" and protecting encryption keys.

  PCI 6.2.4 is a genuine fit via its bullets on attacks against cryptography usage and
  against access-control mechanisms. Note that PCI **12.3.3 is an obligation this feature
  creates, not one it satisfies**: adding a cipher suite means it must appear in a documented
  cryptographic inventory reviewed at least every 12 months, which has been Required since
  31 March 2025. The same duty applies to the TLS, KMS, and Argon2id rows above.

  Two further limits worth stating: encryption does not conceal the *length* of the claim set
  (RFC 8725 §2.4), so token size still leaks roughly how many permissions a principal holds,
  and encrypting the token removes it from your own operators' and your assessor's view,
  which is a real cost to debuggability and evidence gathering.
- **RBAC / multi-tenant isolation.** Both map to access-control controls (least privilege,
  need-to-know). Database-per-tenant is a physical enforcement of logical segregation.
  Note the limit of that enforcement: separate databases answer "whose data can this
  connection reach", not "who is allowed to ask". A validly signed token from tenant A
  presented against tenant B routes correctly to B's database and still leaks nothing, yet
  authenticates a principal with no account in B. Binding the token's tenant claim to the
  resolved tenant is a separate control, and both are needed to claim Req 7 or CC6.3.
- **Rate limiting.** No direct HIPAA technical safeguard (HIPAA handles availability via
  administrative contingency planning, 164.308(a)(7)), hence the blank. PCI 8.3.4 is the
  auth-lockout tie, though that clause number is **unverified** here: PCI-DSS is behind
  registration and nobody on this project has read the text.

  **A correction, and the reason the row is now split in two.** An earlier version of this file
  claimed that "SOC 2 CC6.6 points of focus explicitly include rate limiting and DDoS". That could
  not be substantiated. In the 2017 Trust Services Criteria (including the March 2020 updates) the
  strings "rate limit", "throttl", "denial of service" and "DDoS" do not appear at all, and CC6.6's
  four points of focus are Restricts Access, Protects Identification and Authentication
  Credentials, Requires Additional Authentication or Credentials, and Implements Boundary
  Protection Systems. The 2022 revised points of focus that this document cites could not be
  obtained to check. So the honest mapping rests on the **criterion** rather than a point of focus:
  CC6.6 is "logical access security measures to protect against threats from sources outside its
  system boundaries", which supports the mapping without the word "explicitly" doing work the
  source does not.

  The row is now two rows because one row conflated two controls with different honest answers.
  Application-level rate limiting is something this repository can implement. Volumetric DoS
  defence is not: by the time a request reaches a guard, the connection is accepted, HTTP parsed
  and the tenant resolved, so a flood large enough to matter has already won. That belongs at L3/L4
  in front of the service, the same framing this document already uses for TLS. Leaving them merged
  let one row's status imply the other's.
- **Input validation.** PCI 6.2.4 is direct (prevent injection/tampering in custom
  software). The HIPAA (164.312(c)(1) Integrity) and SOC 2 (CC8.1) ties are indirect.

## Caveats

1. Every framework includes administrative and physical controls that cannot be met in
   application code: HIPAA workforce training and physical safeguards (164.310), PCI
   Requirement 9 (physical access) and Requirement 12 (governance), SOC 2 CC1-CC5. The
   mapped rows cover only the technical-safeguard subset.
2. PCI-DSS applies only if the system is part of the Cardholder Data Environment (stores,
   processes, or transmits account data). Outside the CDE, PCI controls are out of scope.
3. SOC 2 Availability, Confidentiality, Processing Integrity, and Privacy categories are
   optional; only the Security common criteria (CC-series) are mandatory.
4. A blank in the HIPAA column means no directly named control maps, not that the feature
   is irrelevant to security.
5. HHS published a HIPAA Security Rule NPRM in early 2025 that would make several
   currently-Addressable specs Required and add explicit MFA/encryption mandates. It has
   not finalized as of this writing, so the current Addressable status stands. Re-check.
6. PCI sub-requirement numbering is stable across v4.0 and v4.0.1, but a future revision
   could renumber. Always confirm against the version being assessed.

## Sources (verified against primary references)

- HIPAA Security Rule, 45 CFR 164.312 (Technical safeguards): <https://www.law.cornell.edu/cfr/text/45/164.312>
- HIPAA Security Rule, 45 CFR 164.308 (Administrative safeguards): <https://www.law.cornell.edu/cfr/text/45/164.308>
- PCI-DSS v4.0.1 (PCI Security Standards Council): the official standard at <https://www.pcisecuritystandards.org/>
- AICPA 2017 Trust Services Criteria (with revised points of focus, 2022): <https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022>
- HIPAA definitions, 45 CFR 160.103 (ePHI / individually identifiable health information): <https://www.law.cornell.edu/cfr/text/45/160.103>

Token format and its limits (cited in the access-token row):

- RFC 7519, JSON Web Token: §5.2 (`cty` on a nested JWT), §11.2 (sign-then-encrypt order), §12 (privacy considerations): <https://www.rfc-editor.org/rfc/rfc7519>
- RFC 7518, JSON Web Algorithms: §3.1 (`alg` values for JWS, where ES256 is `Recommended+`), §3.4 (digital signature with ECDSA), §4.1 / §5.1 (`alg` and `enc` values for JWE), §4.4 (key wrapping with AES Key Wrap), §8.4 (AES GCM security considerations): <https://www.rfc-editor.org/rfc/rfc7518>
- RFC 7517, JSON Web Key: §4.5 (`kid` is a case-sensitive string, which is why `config_keys.kid` is TEXT), §5 (JWK Set format), §8.5.1 (the `application/jwk-set+json` media type): <https://www.rfc-editor.org/rfc/rfc7517>
- RFC 8615, Well-Known URIs: why the JWKS is served from the origin root rather than under `/api`: <https://www.rfc-editor.org/rfc/rfc8615>
- RFC 8725 (BCP 225), JWT Best Current Practices: §2.3 / §3.3 (validate both layers), §2.4 (length leakage), §3.2 (TLS may suffice), §3.6 (do not compress), §3.11 (explicit typing): <https://www.rfc-editor.org/rfc/rfc8725>
- RFC 9068, JWT Profile for OAuth 2.0 Access Tokens: §2.1 / §2.2 (why this kit does **not** claim `at+jwt`), §6 (the disclosure-to-client threat): <https://www.rfc-editor.org/rfc/rfc9068>
- RFC 9700 (BCP 240), OAuth 2.0 Security Best Current Practice: §2.2.1 (sender-constraining, which this kit does not implement): <https://www.rfc-editor.org/rfc/rfc9700>
- OWASP Password Storage Cheat Sheet (Argon2id parameters): <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

_Citations were verified against 45 CFR Part 164 (eCFR), PCI-DSS v4.0.1, and the AICPA
2017 TSC. Re-verify against the exact framework version in force at assessment time._
