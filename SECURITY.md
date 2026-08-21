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

The pass on 2026-08-21 flagged
[GHSA-ggr8-5vv4-36mx](https://github.com/advisories/GHSA-ggr8-5vv4-36mx), stack exhaustion
(CWE-674) in `deepmerge-ts` below 8.0.0: `deepmerge()` recurses until
`RangeError: Maximum call stack size exceeded` when both inputs carry self-references at the same
property path. It reaches us through a single dependency chain,
`prisma@7.9.1 > @prisma/config@7.9.1 > deepmerge-ts@7.1.5`, which appears more than once in the tree
because `@prisma/client` depends on `prisma` as well. One chain, several entry points into it, no
second route.

**There was nothing upstream to wait for.** `prisma@7.9.1` was the current release and its
`@prisma/config` still pinned `deepmerge-ts` at 7.1.5, so the choice was an override or an entry in
the accepted table above. Fixed with `"deepmerge-ts@7": "^8.0.1"`, scoped to the vulnerable major so
it stops rewriting anything the day Prisma moves to 8 on its own.

The exposure was low, and lower than the other build-time cases: `@prisma/config` merges **this
repository's own** Prisma configuration, so the merged input is authored here rather than supplied by
anyone, and no request path reaches it. As with `js-yaml`, that is an argument for not panicking and
not an argument for annotating it. Removing the vulnerable version keeps the inventory accurate, and
a suppression entry would have left the dependency row of COMPLIANCE.md resting on a footnote.

Crossing a major version needed checking rather than assuming, since 8.0.0 is a breaking release of a
package this repo never calls directly. Verified by resolution and by exercising the only consumer:
`pnpm why deepmerge-ts -r` reports 8.0.1 for every consumer and
`grep -oE 'deepmerge-ts@[0-9]+\.[0-9]+\.[0-9]+' pnpm-lock.yaml | sort -u` yields exactly one
version (the looser `[0-9.]+` also matches the `deepmerge-ts@7` override key, so it reports two), `pnpm audit`
reports no known vulnerabilities, `pnpm test` (248), `pnpm typecheck`, `pnpm lint`, `pnpm format:check` and
`pnpm build` all pass, and `prisma -v` still reports 7.9.1 with a resolving schema engine. **Revisit
when** `@prisma/config` declares `deepmerge-ts` 8 or later, at which point this entry and its override
should be deleted rather than left to rewrite a version nobody asks for.

### One override that is not an advisory fix

`"fastify@5": "^5.12.0"` began as version alignment rather than remediation, and is recorded here so
every entry in `pnpm.overrides` has a reason attached. It has since become both.

**Why it exists.** `@nestjs/platform-fastify` depends on `fastify` EXACTLY, not by range, so the
adapter and not this repo's `services/auth` dependency decides which Fastify actually serves
requests. Bumping the direct dependency alone therefore moved only the type definitions the code
compiles against, leaving two Fastify copies in the tree and newer types describing an older server,
which is a small instance of the skew that keeps `@types/node` majors pinned. The override collapses
both to one version.

**Nest's pin moves, so the gap changes rather than closes.** 11.1.28 pinned `5.10.0`, which is what
made the original skew glaring; 11.2.1 pins `5.11.3`. Do not assume the two are still far apart, and
do not assume they have converged either: check, because the answer decides whether the override is
holding Fastify back or pushing it forward.

**As of 5.12.1 it is remediation too, and this is the important part.** Fastify 5.12.1 fixes two
advisories, both affecting `< 5.12.1`, so the `5.11.3` that Nest pins is vulnerable to both:

- [GHSA-3m5p-2c4r-xxw2](https://github.com/fastify/fastify/security/advisories/GHSA-3m5p-2c4r-xxw2)
  (moderate, CVSS 6.1): the NUMERIC `trustProxy` form stays spoofable, so an attacker with direct
  access to the origin can bypass the proxy guard and inject host headers.
- [GHSA-w2qp-rph6-63g4](https://github.com/fastify/fastify/security/advisories/GHSA-w2qp-rph6-63g4)
  (moderate, CVSS 5.4): a route with a root-level primitive body schema and type coercion validates
  the coerced value and then hands the handler the original, unvalidated one.

**Neither is reachable in this kit as configured, stated precisely because "we use Fastify" is not
the same as "we are exposed".** `trustProxy` is parsed as `.pipe(z.boolean())` in
`packages/config/src/index.ts`, so even `TRUST_PROXY=1` becomes boolean `true` and the hop-count
code path cannot be configured from here at all. And no route declares a Fastify schema: validation
is class-validator DTOs through Nest's pipe, so there is no root-level primitive body to coerce.
Taken anyway, because a downstream consumer who sets a numeric `trustProxy` or adds a Fastify route
schema would be exposed, and because being one minor ahead of Nest's pin is a cost this entry
already accepted.

**`pnpm audit` did not catch either of them, and that is worth writing down.** Both were repository
advisories not yet published to the global database, so the gate reported "No known vulnerabilities
found" against a version affected by two of them. The gate is a floor, not a ceiling: reading the
release notes of anything in the request path is not optional just because the audit is green.

**Verified by resolution**, the way the `find-my-way` override was: `pnpm why fastify -r` reports
5.12.1 for both `services/auth` and `@nestjs/platform-fastify`, and exactly one `fastify` version
remains in the lockfile. The cost, said plainly, is that the adapter runs against a Fastify version
its own maintainers did not pin, which is why the end-to-end smoke test matters more than usual
here. 92 checks and `pnpm verify:claims` both pass on it.

**The override is the single source of truth for the Fastify version, and that has a sharp edge that
has now caught us twice.** An override range is not a floor that drifts upward. `^5.11.0` is
satisfied by 5.11.0, so when Dependabot bumped `services/auth` to `^5.11.3`, `pnpm install` left the
lockfile on 5.11.0 and the "upgrade" changed nothing; `^5.11.3` then did the same to the `^5.12.0`
bump. A bump that appears to land and does nothing is worse than one that fails, because CI stays
green. So when raising Fastify, **change the override too, and confirm by resolution**:

```bash
pnpm why fastify -r | grep -A1 platform-fastify   # must report the version you intended
grep -E '^  fastify@[0-9]' pnpm-lock.yaml         # must be exactly one line
```

The same applies to every entry in `pnpm.overrides`: each one takes that dependency's version out of
the hands of the package that declares it, including out of Dependabot's.

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
