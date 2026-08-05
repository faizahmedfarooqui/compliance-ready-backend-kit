# Documentation

Everything needed to run, understand, extend and audit the compliance-ready backend kit.

The [repository README](../README.md) is the front door: what the kit is, why it exists, and a
quick start. These pages go deeper and are organised by the task you are trying to do.

## Start here

| Page | Read it when |
| --- | --- |
| [Introduction](introduction.md) | You want to know what this kit is, and what it deliberately is not |
| [Getting started](getting-started.md) | You want it running locally and a first authenticated request made |
| [Configuration](configuration.md) | You are setting environment variables, or one of them refused to boot |

## Understanding the system

| Page | Covers |
| --- | --- |
| [Architecture](architecture.md) | The monorepo, which package owns what, and why the boundaries fall where they do |
| [Multi-tenancy](multi-tenancy.md) | Database-per-tenant, the master registry, provisioning, and the two Prisma schemas |
| [Request lifecycle](request-lifecycle.md) | Every stage a request passes through, in order, and where to put your own code |

## Building on it

| Page | Covers |
| --- | --- |
| [Authentication](authentication.md) | Nested JWT access tokens, login, and the guards that verify them |
| [Authorization](authorization.md) | RBAC, the permission catalogue, and how to add a permission or protect a route |
| [Key management](key-management.md) | The `config_keys` registry, rotation, the published JWKS, and the `KeyProvider` port |
| [Audit log](audit-log.md) | The per-tenant hash chains, emitting events, and proving the log has not been edited |
| [Rate limiting](rate-limiting.md) | The two tiers, the `trustProxy` decision, and what happens when Redis is down |

## Reference

| Page | Covers |
| --- | --- |
| [API reference](api-reference.md) | Every route, its guards, and worked request and response examples |
| [Response contract](responses.md) | The success envelope and the RFC 9457 error shape |
| [Error catalogue](../problems.md) | Every problem code, with the status it maps to |
| [Operations](operations.md) | Every CLI command, and the runbooks for rotation and verification |
| [Testing](testing.md) | What is unit tested, what is only provable against a real database, and why |
| [Compliance mapping](compliance.md) | How to read [COMPLIANCE.md](../COMPLIANCE.md), and what the kit does not claim |

## A note on how these docs are written

Two conventions worth knowing, because they are load-bearing rather than stylistic.

**Nothing here describes a capability the kit does not have.** Where something is missing, partial,
or true only under a deployment posture the kit does not ship, the page says so at that point rather
than in a caveats section nobody reads. If a page and [COMPLIANCE.md](../COMPLIANCE.md) ever
disagree, COMPLIANCE.md's Status column is the answer, and the page is a bug.

**Reasons are documented alongside decisions.** Several choices here look wrong until you know what
they are avoiding, and the ones that look most wrong are usually the ones that cost the most to
rediscover. Where a page explains why something is not done the obvious way, that explanation is the
point of the page.
