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
  credentials in `docker-compose.yml`, and the `KEY_ENCRYPTION_KEY` placeholder in
  `.env.example` and `.github/workflows/ci.yml`, exist for local development and CI. They are
  committed on purpose, are therefore public, and are labelled as such. The token signing and
  encryption keys are **not** among them: those are generated per deployment by
  `pnpm keys:init` and stored wrapped in `config_keys`, so there is no committed value to find.
- Missing hardening in example or documentation code, absent a concrete exploit.
- Vulnerabilities in Node, Postgres, Redis, NestJS, or Prisma themselves. Report those
  upstream; tell us if this kit's usage makes one materially worse.
- Reports produced by running a scanner and pasting its output, with no analysis of
  whether the finding is reachable here.

## Dependency advisories, and the ones we accept

CI runs `pnpm audit --audit-level=high` as a **gate**, not a report, plus CodeQL, gitleaks over
full history, and dependency review on pull requests. See
[.github/workflows/security.yml](.github/workflows/security.yml).

Two things about that gate are deliberate.

**It is allowed to fail the build.** A check that cannot fail is theatre, and this is one of the
rows COMPLIANCE.md marks as a real control. When an advisory appears, fix it or record an exception
here. Do not lower the threshold.

**Exceptions are documented, not silent.** Suppressing an advisory without saying why is
indistinguishable from not noticing it. Every entry in `pnpm.auditConfig.ignoreGhsas` must have a
matching entry below, with the reasoning and what would make us revisit it.

### Accepted advisories

| Advisory | Package | Why accepted | Revisit when |
| --- | --- | --- | --- |
| [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg) | `brace-expansion` 1.1.16 / 2.1.2 | Denial of service via unbounded expansion. **Not in the production dependency closure** (`pnpm why --prod` returns nothing): it reaches us only through ESLint's tooling, so the exposure is a developer's own build. The fix exists only in 5.0.8, and 1.1.16 and 2.1.2 are already the newest releases on those major lines, so there is nothing to upgrade to without a breaking major bump of the consumers. | A patched 1.x or 2.x is published, or the consuming tooling moves to 5.x. |

### Fixed rather than accepted

For the record, because it shows the gate working: the first run flagged
[GHSA-c96f-x56v-gq3h](https://github.com/advisories/GHSA-c96f-x56v-gq3h), an HTTP/2 denial of
service in `find-my-way` at or below 9.6.0 — the router underneath Fastify, squarely in the
production path. `fastify` itself allows `^9.6.0` and so would take the fix, but
`@nestjs/platform-fastify` pins `9.6.0` exactly. Resolved with a `pnpm.overrides` entry scoped to
the 9.x line (`"find-my-way@9": "^9.7.0"`), which leaves an unrelated 8.x consumer in the tooling
alone. Verified by confirming both `fastify` and `@nestjs/platform-fastify` now resolve 9.7.0.

Adding OpenAPI documentation in v0.2 flagged a second one:
[GHSA-pm4m-ph32-ghv5](https://github.com/advisories/GHSA-pm4m-ph32-ghv5), exponential parsing time in
`js-yaml` flow collections, reachable through `@nestjs/swagger`. Fixed the same way, with
`"js-yaml@5": "^5.2.2"` scoped to the 5.x line, which at the time left the unrelated 4.x consumer in
the tooling alone, and verified by resolving 5.2.2 and confirming `/docs/openapi.yaml` still renders.

Worth noting what the exposure actually was, because "high" and "exposed" are not the same thing: the
advisory is about PARSING adversarial YAML, and this service only ever SERIALISES its own OpenAPI
document. There was no path by which a caller's input reached the parser. It was still fixed rather
than annotated, because an accurate dependency inventory is worth more than an argument, and the next
person to add a YAML-parsing feature should inherit a patched version rather than that argument.

The weekly pass on 2026-08-10 came back for the 4.x consumer that the `js-yaml@5` override had left
alone: [GHSA-5p4m-2wfm-xmqj](https://github.com/advisories/GHSA-5p4m-2wfm-xmqj), quadratic CPU
consumption resolving the `!!omap` tag, covering `>=4.0.0 <4.3.1`. It arrives through `@nestjs/cli`,
`fork-ts-checker-webpack-plugin` and `cosmiconfig`, so like `brace-expansion` it is build-time tooling
rather than the request path. Fixed with `"js-yaml@4": "^4.3.1"` on the same reasoning as the
paragraph above, and for one more: the audit gate does not grade on reachability, and teaching it to
would mean deciding, every week and by hand, which advisories are allowed to stay red.

### One override that is not an advisory fix

`"fastify@5": "^5.11.0"` is version alignment, not remediation, and is recorded here so every entry in
`pnpm.overrides` has a reason attached. `@nestjs/platform-fastify` depends on `fastify` exactly, at
`5.10.0`, so the adapter, not this repo's `services/auth` dependency, decides which Fastify actually
serves requests. Bumping the direct dependency alone therefore moved only the type definitions the
code compiles against, leaving two Fastify copies in the tree and 5.11.0 types describing a 5.10.0
server, which is a small instance of the skew that keeps `@types/node` majors pinned. The override
collapses both to 5.11.0 and picks up 5.11.0's fix for honouring quoted strings in `Content-Type`
parameter values, a parameter this service reads on every request and the same class of parsing bug
behind four Fastify advisories. Verified the way the `find-my-way` override was, by resolution:
`pnpm why fastify -r` reports 5.11.0 for both `services/auth` and `@nestjs/platform-fastify`, and one
`fastify@5.11.0` remains in the lockfile. The cost, stated plainly, is that the adapter now runs
against a Fastify minor its own maintainers did not pin, which is why the end-to-end smoke test
matters more than usual here.

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
