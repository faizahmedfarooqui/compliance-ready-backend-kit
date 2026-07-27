# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's [Report a
vulnerability](https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/security/advisories/new)
form, which opens a private advisory visible only to the maintainers. If that is
unavailable to you, email **faizz.af@gmail.com** with `SECURITY` in the subject line.

Useful things to include, as far as you have them:

- the affected version or commit
- what an attacker gains, and what access they need to start
- steps to reproduce, ideally against the local `docker compose` setup
- whether you are willing to be credited, and under what name

### What to expect

This project is maintained by one person as open source, so please read these as
good-faith intentions rather than a contractual SLA:

| Stage | Target |
| --- | --- |
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or documented mitigation for a confirmed high-severity issue | within 30 days |

You will get a straight answer either way, including "this is a known gap, here is where
it is written down" or "this is out of scope, here is why". Reporters are credited in the
release notes unless they ask not to be.

Please give a reasonable window for a fix before publishing. There is no bug bounty.

## Scope

In scope: anything in this repository. The findings most worth reporting are those that
break the properties the kit actually claims:

- **Cross-tenant access** of any kind: reading, writing, or acting inside a tenant you
  hold no account in. This is the kit's central claim and its most serious failure mode.
- Authentication bypass, token forgery, or accepting a token outside its intended tenant.
- Privilege escalation, including any path to a permission the caller was not granted.
- SQL injection, particularly around identifier interpolation in tenant provisioning.
- Secret disclosure through logs, error responses, or committed files.
- Dependency vulnerabilities that are actually reachable from this code.
- Anything that gets an access token accepted when it should not be: a forged or replayed
  nested JWT, a token accepted without its inner signature being verified, algorithm or
  `cty` confusion between the JWE and JWS layers, or a token from one tenant accepted by
  another.

Out of scope:

- The **known gaps documented in the README's Status section**. They are deliberate and
  disclosed, so a report that `POST /api/tenants` is unauthenticated tells us nothing new.
  A way to exploit one of them that the README does not anticipate is very much in scope.
- Findings that depend on the deliberately insecure local defaults: the `postgres/postgres`
  credentials in `docker-compose.yml`, and the `JWT_SIGNING_KEY` / `JWT_ENCRYPTION_KEY`
  placeholders in `.env.example` and `.github/workflows/ci.yml`, exist for local development
  and CI. They are committed on purpose, are therefore public, and are labelled as such.
- Missing hardening in example or documentation code, absent a concrete exploit.
- Vulnerabilities in Node, Postgres, Redis, NestJS, or Prisma themselves. Report those
  upstream; tell us if this kit's usage makes one materially worse.
- Reports produced by running a scanner and pasting its output, with no analysis of
  whether the finding is reachable here.

## What this project is not

This kit provides technical scaffolding that supports compliance controls. It is **not** a
certification, an assessment, or a guarantee. It has not been reviewed by a QSA, a CPA
firm, or any third-party assessor. See [COMPLIANCE.md](./COMPLIANCE.md) for what each
capability does and does not cover, and treat the control mapping there as a starting
point for your own assessment rather than evidence for it.

## Security practices in this repository

- **No secrets are committed.** `.env.example` holds non-secret pointers only. In
  production, secrets are expected to load at runtime from KMS or Secrets Manager into
  typed config, never to sit in `process.env`.
- **Clean-room origin.** All code is written from public specifications and standards.
  Nothing is copied or adapted from any employer or client.
- **Isolation is enforced by Postgres**, not by application predicates. See the README.
- Argon2id parameters, JWT settings, and the permission catalogue are each declared in one
  place, so a security-relevant value has a single readable answer.
