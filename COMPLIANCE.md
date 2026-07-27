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

| Capability | HIPAA (45 CFR) | PCI-DSS v4.0.1 | SOC 2 (TSC) |
| --- | --- | --- | --- |
| Append-only audit logging | 164.312(b); 164.308(a)(1)(ii)(D) | Req 10 (10.2, 10.3.2) | CC7.2 |
| Encryption at rest | 164.312(a)(2)(iv) | Req 3 (3.5, 3.5.1) | CC6.1 |
| Encryption in transit (TLS) | 164.312(e)(1); 164.312(e)(2)(ii) | Req 4 (4.2.1) | CC6.7 |
| Secrets management (KMS envelope encryption) | 164.312(a)(2)(iv) | Req 3 (3.6, 3.7) | CC6.1 |
| Authentication (MFA / passkeys / WebAuthn) | 164.312(d) | Req 8 (8.4, 8.5) | CC6.1 |
| Password storage (Argon2id KDF) | 164.312(d) | Req 8 (8.3.2) | CC6.1 |
| Access-token confidentiality (nested JWT: signed, then encrypted) | 164.308(a)(1)(ii)(B) | Req 6 (6.2.4); Req 12 (12.3.3) | CC6.1 |
| RBAC / access control | 164.312(a)(1); 164.312(a)(2)(i); 164.308(a)(4) | Req 7 | CC6.3 |
| Multi-tenant isolation (database-per-tenant) | 164.312(a)(1) | Req 7 | CC6.1 |
| Rate limiting / DoS protection | (none, see notes) | Req 6 (6.4.2); Req 8 (8.3.4) | CC6.6 |
| Input validation | 164.312(c)(1) | Req 6 (6.2.4) | CC8.1 |
| Structured logging + monitoring (OpenTelemetry) | 164.312(b); 164.308(a)(1)(ii)(D) | Req 10 | CC7.2 |
| Vulnerability / dependency management | 164.308(a)(8); 164.308(a)(5)(ii)(B) | Req 6 (6.3.1-6.3.3); Req 11 (11.3) | CC7.1 |

## Notes on the mappings

- **Audit logging.** PCI 10.3.2 (protect audit logs from modification) is the direct
  analogue of append-only immutability. HIPAA 164.308(a)(1)(ii)(D) activity review is
  Required. SOC 2 CC7.2 covers monitoring components for anomalies.
- **Encryption at rest / in transit.** Both HIPAA specs here, 164.312(a)(2)(iv) and
  164.312(e)(2)(ii), are **Addressable** (implement, or document why not and adopt an
  equivalent). Addressable does not mean optional. PCI 3.5 is the parent standard; the
  specific "render stored PAN unreadable" obligation is 3.5.1.
- **Secrets management.** No HIPAA safeguard names key management; it sits under the
  encryption mechanism (Addressable). PCI is the strongest fit: 3.6 (key-management
  processes) and 3.7 (key lifecycle) map directly to KMS envelope encryption.
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
  auth-lockout tie; SOC 2 CC6.6 points of focus explicitly include rate limiting and DDoS.
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
- RFC 7518, JSON Web Algorithms: §3.2 (HMAC key size), §4.1 / §5.1 (`alg` and `enc` values), §8.4 (AES-GCM key-use limits): <https://www.rfc-editor.org/rfc/rfc7518>
- RFC 8725 (BCP 225), JWT Best Current Practices: §2.3 / §3.3 (validate both layers), §2.4 (length leakage), §3.2 (TLS may suffice), §3.6 (do not compress), §3.11 (explicit typing): <https://www.rfc-editor.org/rfc/rfc8725>
- RFC 9068, JWT Profile for OAuth 2.0 Access Tokens: §2.1 / §2.2 (why this kit does **not** claim `at+jwt`), §6 (the disclosure-to-client threat): <https://www.rfc-editor.org/rfc/rfc9068>
- RFC 9700 (BCP 240), OAuth 2.0 Security Best Current Practice: §2.2.1 (sender-constraining, which this kit does not implement): <https://www.rfc-editor.org/rfc/rfc9700>
- OWASP Password Storage Cheat Sheet (Argon2id parameters): <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

_Citations were verified against 45 CFR Part 164 (eCFR), PCI-DSS v4.0.1, and the AICPA
2017 TSC. Re-verify against the exact framework version in force at assessment time._
