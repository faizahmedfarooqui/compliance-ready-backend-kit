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

**Settings live in `pnpm-workspace.yaml`, not `package.json`.** pnpm 11 stopped reading the
`pnpm` field in `package.json`, and it warns rather than erroring, so an unmigrated `overrides`
block silently stops pinning anything. If you are looking for these settings and cannot find
them, that is why.

**Exceptions are documented, not silent.** Suppressing an advisory without saying why is
indistinguishable from not noticing it. Every entry in `auditConfig.ignoreGhsas` (in `pnpm-workspace.yaml`) must have a
matching entry below, with the reasoning and what would make us revisit it.

### Accepted advisories

**None, as of 2026-09-30.** When one is needed, add a row here giving the advisory, the package and
version, why it is accepted, and what would make us revisit it, and add its id to `ignoreGhsas`.

The last entry was [GHSA-mh99-v99m-4gvg](https://github.com/advisories/GHSA-mh99-v99m-4gvg), denial
of service via unbounded expansion in `brace-expansion`, accepted because the fix existed only in 5.0.8
while 1.1.16 was the newest 1.x release. Its own revisit condition ("a patched 1.x or 2.x is published")
then came true without anyone noticing: the advisory lists 1.1.17 as patched, and the 1.x floor has
been 1.1.18 since 2026-08-06. It was removed from `ignoreGhsas` on 2026-09-30 rather than left in
place, because an exception that outlives its reason stops recording a decision and starts hiding a
regression: anything that pulled a vulnerable 1.x back into the tree would have passed the gate.

### Fixed rather than accepted

For the record, because it shows the gate working: the first run flagged
[GHSA-c96f-x56v-gq3h](https://github.com/advisories/GHSA-c96f-x56v-gq3h), an HTTP/2 denial of
service in `find-my-way` at or below 9.6.0 — the router underneath Fastify, squarely in the
production path. `fastify` itself allows `^9.6.0` and so would take the fix, but
`@nestjs/platform-fastify` pins `9.6.0` exactly. Resolved with an `overrides` entry scoped to
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
reports no known vulnerabilities, and `pnpm test`, `pnpm typecheck`, `pnpm lint`, `pnpm format:check` and
`pnpm build` all pass, and `prisma -v` still reports 7.9.1 with a resolving schema engine. **Revisit
when** `@prisma/config` declares `deepmerge-ts` 8 or later, at which point this entry and its override
should be deleted rather than left to rewrite a version nobody asks for.

The 2026-09-16 pass came back with eleven findings across seven advisories, and the shape of it
is the reason for the warning at the end of this section.

`fast-uri` ([GHSA-5jgf-p345-68v8](https://github.com/advisories/GHSA-5jgf-p345-68v8),
[GHSA-f65p-4m7j-42xc](https://github.com/advisories/GHSA-f65p-4m7j-42xc),
[GHSA-fph4-wmhf-6fwf](https://github.com/advisories/GHSA-fph4-wmhf-6fwf),
[GHSA-jqff-g426-hqxp](https://github.com/advisories/GHSA-jqff-g426-hqxp), patched `>=4.1.3` and
`>=3.1.6`) and `js-yaml`
([GHSA-2883-xcg3-v3hh](https://github.com/advisories/GHSA-2883-xcg3-v3hh), patched `>=4.3.2`)
were both **already overridden here**, and both were sitting at exactly their floor: 4.1.2
against an `^4.1.2` override, 3.1.5 against `^3.1.5`, 4.3.1 against `^4.3.1`. Dependabot cannot
fix these, because it does not manage this file, and a caret range is satisfied by its own floor
so `--frozen-lockfile` never drifts upward. **An override silently becomes a ceiling the moment
its floor goes vulnerable.** Fixed by raising all three floors to the patched versions, which
resolved 4.1.5, 3.1.8 and 4.3.2.

`mysql2` ([GHSA-3f6p-5ww8-9rcr](https://github.com/advisories/GHSA-3f6p-5ww8-9rcr),
[GHSA-rgwj-5xj2-c3m3](https://github.com/advisories/GHSA-rgwj-5xj2-c3m3), patched `>=3.23.1`) was
new: no override, reaching us at 3.15.3 only through Prisma's MySQL support. This repo uses
`@prisma/adapter-pg` and every schema declares `provider = "postgresql"`, so **that code path is
never executed here**. Fixed anyway with `mysql2@3: ^3.24.4`, on the same reasoning as `js-yaml`
above: an accurate dependency inventory is worth more than an argument about reachability, and
the next person to add a MySQL adapter should inherit a patched version rather than that argument.

The 2026-09-30 pass came back with nine findings across six advisories, all published on
2026-09-29, the day after the last green scheduled run. Nothing on our side had changed.

`fast-uri` ([GHSA-hrr3-gc8f-f4qj](https://github.com/advisories/GHSA-hrr3-gc8f-f4qj),
[GHSA-jvvf-x445-j334](https://github.com/advisories/GHSA-jvvf-x445-j334), patched `>=4.1.5`, and
`>=3.1.8` for the first) is in the production path, since Fastify's validation and serialisation both
run through it. The 3.x line was already on 3.1.8. The 4.x line was on 4.1.4, and should not have
been: the 2026-09-16 pass above had resolved 4.1.5, then Dependabot's grouped update #55, merged the
same day, regenerated the lockfile and moved it back to 4.1.4. The `^4.1.3` floor permitted that, no
advisory covered 4.1.4 yet, and nothing looks for a downgrade, so nothing noticed.

`js-yaml` ([GHSA-r3ph-w7gj-g6xm](https://github.com/advisories/GHSA-r3ph-w7gj-g6xm), patched `>=5.4.1`)
was the override working backwards. `@nestjs/swagger` 12.0.1 declares `js-yaml` 5.4.1 exactly, which
is the patched version, and the `^5.2.2` override rewrote that into a range the locked 5.3.0 already
satisfied. Without the override we would not have been exposed at all. `find-my-way` had the same
shape with no advisory attached: `@nestjs/platform-fastify` declares 9.9.0, the `^9.7.0` override held
it at 9.7.0, and two copies of the router shipped, 9.9.0 under Fastify and 9.7.0 under the adapter.

`brace-expansion` ([GHSA-qhr7-859c-m2p7](https://github.com/advisories/GHSA-qhr7-859c-m2p7) and
[GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p), both high, and
[GHSA-q2hr-2g5m-vwhr](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr); `>=1.1.21` and `>=5.0.12`
are patched for all three) reaches us only through ESLint and the Nest CLI, and was fixed on the same
reasoning as `mysql2`.

The same pass read the request-path packages' own repository advisories, which the gate cannot see,
and found two more affecting `main` that are in neither the global database nor `pnpm audit`'s output:
[GHSA-9c5c-9qcx-q35q](https://github.com/nestjs/nest/security/advisories/GHSA-9c5c-9qcx-q35q) (high,
2026-09-15), a path-scoped middleware bypass through absolute-form request targets in
`@nestjs/platform-fastify` `>=12.0.0 <12.0.2`, and
[GHSA-r799-r9gc-m956](https://github.com/fastify/fastify-static/security/advisories/GHSA-r799-r9gc-m956)
(moderate, 2026-09-17), a route guard and `allowedPath` bypass on case-insensitive filesystems in
`@fastify/static` below 10.1.4. Neither is reachable here as configured: the service applies no
path-scoped middleware at all, since authentication and authorization are guards, and `@fastify/static`
is used only by `@nestjs/swagger`, which registers it over the public `swagger-ui-dist` assets with no
`allowedPath` and no route guard, so the case-folding bypass has no restriction to get around. It is
served by default, since `API_DOCS_ENABLED` defaults to on; turning it off in production, as
[configuration](docs/configuration.md) recommends, removes it from the request path entirely.
Both are fixed by the Nest 12.1.1 and `@fastify/static` 10.1.5 updates taken in the same change.
Nest 12.1.1 also brings in a runtime dependency that 12.0.1 did not have, `@fastify/middie`, which
the adapter registers on every request; it arrives at 9.3.4, the release that fixes its own half of
the same bug ([GHSA-hx87-8wv7-pjv8](https://github.com/fastify/middie/security/advisories/GHSA-hx87-8wv7-pjv8),
critical), and it has had three critical advisories this year, so it is on the list of repositories
the dependency pass now reads directly.

**Fixed by setting every floor to the version that resolution produced and the suites were run
against, not to the lowest version an advisory calls patched**: `fast-uri@4` 4.2.1, `fast-uri@3`
3.1.8, `js-yaml@5` 5.4.2 (what `@nestjs/swagger` 12.0.2 itself declares), `brace-expansion@1` 1.1.21,
`brace-expansion@5` 5.0.12, `find-my-way@9` 9.9.0 (what the adapter declares), `fastify@5` 5.12.5, and
`deepmerge-ts@7` 8.0.2, which had the same slack as `fast-uri` without yet having been caught by it.
`fast-uri` 4.2.0 and 4.2.1 are bug-fix releases from the Fastify maintainers, inside the `^4.0.0` that
Fastify declares, and a fresh install of Fastify resolves them anyway. Verified by resolution (one
version per overridden major), `pnpm audit` reporting no known vulnerabilities with `ignoreGhsas`
empty, and at runtime: the 92-check smoke suite, the slowloris probe, both audit probes against the
master chain and a freshly provisioned tenant, and the API docs UI served through `@fastify/static`.

**The operational lesson, now learned three ways.** Raising a dependency is not enough when that
dependency is overridden; the override is the real version. After any advisory on an overridden
package, raise the floor here and confirm by resolution, not by the `package.json` entry. Set the floor
to the version resolution produced, because a floor below it lets the next lockfile rewrite slide back
down inside the range without any check noticing. And when a consumer starts declaring a version at or
above the floor by itself, check whether the override is holding it back: `js-yaml` and `find-my-way`
were both pinned below what the packages that use them ask for.

### Install scripts are denied by default

`pnpm-workspace.yaml` carries an `allowBuilds` map, and anything absent from it is denied.
`strictDepBuilds` defaults to true, so an install that encounters an unreviewed build script
**fails** rather than warning. Four dependencies declare one; three are allowed and one is not:

| Package | Allowed | Why |
| --- | --- | --- |
| `argon2` | yes | Native module, compiled or resolved by `node-gyp-build`. Password hashing does not work without it. |
| `prisma` | yes | `preinstall` entry point. |
| `@prisma/engines` | yes | `postinstall` places the query and schema engines. |
| `@scarf/scarf` | **no** | `postinstall` runs `node ./report.js`, which is install telemetry. Listed explicitly as `false` rather than merely omitted, so the intent is on the record: nothing here phones home on install. |

**This is the control CVE-2025-54313 actually needed.** The malicious `eslint-config-prettier`
releases carried their payload in an install script, not in the linter's own code, so no amount
of care about which linter to use would have helped. Denying scripts by default would have.

Note what it does not do: it stops a package from executing at install time, not from being
malicious when imported. A compromised library that your code calls still runs.

### One override that is not an advisory fix

`"fastify@5"` began as version alignment rather than remediation, and is recorded here so
every entry in `overrides` has a reason attached. It has since become both.

**Why it exists.** `@nestjs/platform-fastify` depends on `fastify` EXACTLY, not by range, so the
adapter and not this repo's `services/auth` dependency decides which Fastify actually serves
requests. Bumping the direct dependency alone therefore moved only the type definitions the code
compiles against, leaving two Fastify copies in the tree and newer types describing an older server,
which is a small instance of the skew that keeps `@types/node` majors pinned. The override collapses
both to one version.

**Nest's pin moves, so the gap changes rather than closes.** 11.1.28 pinned `5.10.0`, which is what
made the original skew glaring; 11.2.1 pinned `5.11.3`, 12.0.1 pinned `5.12.1`, and 12.1.1 pins
`5.12.5`, which as of 2026-09-30 is exactly the override's floor, so for the moment the override
neither holds Fastify back nor pushes it forward. Do not assume the two are still far apart, and
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

**Every Fastify security release since has arrived the same way, and the record is kept because it
is not flattering.** 5.12.2 fixed four high-severity advisories, published 2026-09-04:
[GHSA-667r-xxjv-c9mm](https://github.com/fastify/fastify/security/advisories/GHSA-667r-xxjv-c9mm)
(request body replacement through an `$async` validation result),
[GHSA-p68q-wchp-6fh7](https://github.com/fastify/fastify/security/advisories/GHSA-p68q-wchp-6fh7)
(malformed URLs reaching another plugin's not-found handler),
[GHSA-hwr6-493r-vm6h](https://github.com/fastify/fastify/security/advisories/GHSA-hwr6-493r-vm6h)
(a boolean `false` schema skipped rather than enforced) and
[GHSA-9q9j-q6p8-xq58](https://github.com/fastify/fastify/security/advisories/GHSA-9q9j-q6p8-xq58)
(header schema `dependencies` never matching lowercased headers). 5.12.5 fixed
[GHSA-4mh8-r7rc-xpvc](https://github.com/fastify/fastify/security/advisories/GHSA-4mh8-r7rc-xpvc)
(moderate, 2026-09-16), a denial of service through an unhandled exception on HTTP/2 trailer
responses. As of 2026-09-30 **none of the five is in the global advisory database that `pnpm audit`
reads**, so the gate has never reported any of them. The lockfile held 5.12.1 from 2026-08-28 to
2026-09-16, so `main` ran a Fastify affected by all four high advisories for twelve days, and it left
5.12.1 through a routine Dependabot group (#55) rather than because anyone had seen them. **None was
reachable here as configured**, checked afterwards rather than assumed: three need a Fastify route
schema (an `$async` one, a `false` one, or a header schema using `dependencies`), and no route declares
any schema, since validation is class-validator DTOs through Nest's pipe; the fourth matters where a
not-found handler serves protected data, and this kit registers none of its own, so an unmatched
route gets the generic 404 problem body. The HTTP/2 one needs the adapter created with `http2`, which
it is not. What would have caught them in time is reading Fastify's security advisories directly, which
is now part of every pass.

**Verified by resolution**, the way the `find-my-way` override was: `pnpm why fastify -r` reports
one version of `fastify` for both `services/auth` and `@nestjs/platform-fastify`. That version was
5.12.1 when this entry was written and is **5.12.5** as of 2026-09-30; re-run the commands below
rather than trusting this sentence, which is exactly the kind of claim that goes stale. Whenever the
floor is ahead of Nest's pin, the cost, said plainly, is that the adapter runs against a Fastify version
its own maintainers did not pin, which is why the end-to-end smoke test matters more than usual
here. 92 checks and `pnpm verify:claims` both pass on it.

**The override is the single source of truth for the Fastify version, and that has a sharp edge that
keeps catching us:** twice on `fastify` below, then again on `fast-uri` and `js-yaml` in the
2026-09-16 pass above, and on `fast-uri`, `js-yaml` and `find-my-way` in the 2026-09-30 one. An override range is not a floor that drifts upward. `^5.11.0` is
satisfied by 5.11.0, so when Dependabot bumped `services/auth` to `^5.11.3`, `pnpm install` left the
lockfile on 5.11.0 and the "upgrade" changed nothing; `^5.11.3` then did the same to the `^5.12.0`
bump. A bump that appears to land and does nothing is worse than one that fails, because CI stays
green. So when raising Fastify, **change the override too, and confirm by resolution**:

```bash
pnpm why fastify -r | grep -E '^fastify@|Found [0-9]+ version'   # the version, and that there is one
# Full semver only, deduped, and quote-tolerant: the loose `fastify@[0-9]` also matches
# the `fastify@5:` override key in the lockfile's own overrides block, and pnpm quotes
# scoped keys (`'@fastify/static@10.1.3':`) so a pattern without `'?` finds nothing for
# them. Applies to every override, not just this one.
grep -oE "^  '?fastify@[0-9]+\.[0-9]+\.[0-9]+" pnpm-lock.yaml | tr -d " '" | sort -u
```

The same applies to every entry in `overrides`: each one takes that dependency's version out of
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
