# syntax=docker/dockerfile:1
#
# auth-service, built from the pnpm workspace.
#
# Three targets, and the middle one exists because of a real operational problem rather than for tidiness:
#
#   builder    installs, generates the Prisma clients, compiles every workspace package
#   migrator   builder plus the prisma CLI, for `migrate deploy` and the key bootstrap
#   runtime    the default. Serves the API and NOTHING else
#
# WHY MIGRATIONS ARE NOT IN THE RUNTIME IMAGE. `prisma migrate deploy` needs the prisma CLI, which is a
# devDependency, and the runtime stage installs production dependencies only. That is the right way
# round: a container that can serve traffic should not also hold the tool that can rewrite the schema,
# and this repository's audit-log design depends on the difference. The immutability SQL is written so
# that the role which OWNS the tables is not the role the service connects as, and an image that could
# do both would quietly collapse that distinction. See docs/deployment.md.
#
# Debian slim rather than Alpine, deliberately. argon2 ships prebuilt binaries against glibc; on musl
# it compiles from source, which means dragging a C toolchain into the image and hoping the build
# succeeds on every architecture you deploy to. The password KDF is not the place to accept that.

# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim AS builder

WORKDIR /app

# corepack pins pnpm from the "packageManager" field in package.json, so the image cannot drift from
# what CI and developers use. Copying package.json first is what makes that possible.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN corepack enable && corepack install

# Manifests before sources, so a source-only change does not invalidate the install layer.
COPY packages/common/package.json      packages/common/
COPY packages/config/package.json      packages/config/
COPY packages/crypto/package.json      packages/crypto/
COPY packages/db/package.json          packages/db/
COPY services/auth/package.json        services/auth/

# packages/db has a postinstall that runs `prisma generate`, so the schemas and the two Prisma config
# files have to be present BEFORE the install, not after it. Without them the install fails on a
# missing schema, which reads as a lockfile problem and is not one.
COPY packages/db/prisma/               packages/db/prisma/
COPY packages/db/prisma.master.config.ts packages/db/prisma.tenant.config.ts packages/db/

RUN pnpm install --frozen-lockfile

# Now the sources, then build every package in dependency order (`pnpm -r build`).
COPY tsconfig.base.json ./
COPY packages/ packages/
COPY services/ services/
RUN pnpm build

# ---------------------------------------------------------------------------
# migrator
#
# Run this to apply the master schema and bootstrap the token keys. It keeps the dev dependencies, so
# it is larger than the runtime image and is not meant to serve traffic:
#
#   docker run --rm --env-file .env <image>:migrator pnpm db:migrate
#   docker run --rm --env-file .env <image>:migrator pnpm keys:init
# ---------------------------------------------------------------------------
FROM builder AS migrator
ENV NODE_ENV=production
CMD ["pnpm", "db:migrate"]

# ---------------------------------------------------------------------------
# pruned: resolve the workspace into a self-contained production tree
#
# `pnpm deploy` turns the workspace links into a real directory: services/auth plus the four
# @compliance-kit/* packages, production dependencies only.
#
# --ignore-scripts is REQUIRED, not an optimisation. packages/db's postinstall calls the prisma CLI,
# which --prod has just excluded, so without this the deploy fails at its last step. Skipping it is
# safe because the builder already compiled the generated clients into dist; nothing is left to
# generate.
#
# What this tree must carry beyond dist/, and the reason the runtime stage copies rather than rebuilds:
# ConnectionManager reads sql/tenant-schema.sql and sql/audit-immutability.sql at PROVISIONING time, via
# path.resolve(__dirname, "..", "sql", ...). Those are runtime inputs, not build artefacts. Miss them
# and the service starts, serves health checks, and then fails the first time a tenant is created.
# ---------------------------------------------------------------------------
FROM builder AS pruned
RUN pnpm deploy --filter @compliance-kit/auth-service --prod --ignore-scripts /deploy

# ---------------------------------------------------------------------------
# runtime: the default target
# ---------------------------------------------------------------------------
FROM node:24-bookworm-slim AS runtime

# curl is here for the HEALTHCHECK below and is the only addition to the base image. Nothing else is
# installed: no shell utilities, no build toolchain, no prisma CLI.
RUN apt-get update \
  && apt-get install --no-install-recommends -y curl \
  && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
WORKDIR /app

# node:24 already carries an unprivileged `node` user (uid 1000). Own the files as that user and run as
# it, so a compromise inside the container is not root inside the container.
COPY --from=pruned --chown=node:node /deploy /app

USER node
EXPOSE 3011

# The container is unhealthy until the HTTP server actually accepts a connection, which is a different
# claim from "the process is alive": this service deliberately boots when Redis is unreachable and says
# so, so process liveness alone would mark a degraded instance healthy.
#
# /api/health is exempt from rate limiting on purpose (a 429'd liveness probe gets the container killed
# mid-incident), so probing it cannot consume a caller's budget.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT:-3011}/api/health" > /dev/null || exit 1

# `dist/main.js`, not `services/auth/dist/main.js`: `pnpm deploy` places the DEPLOYED PACKAGE at the
# root of its output directory and puts its workspace dependencies under node_modules/@compliance-kit/*,
# so the monorepo's directory layout does not survive into the image. Worth stating because the wrong
# path builds a perfectly good image that exits immediately with MODULE_NOT_FOUND.
#
# No shell form, so the process is PID 1 and receives SIGTERM directly. NestJS shutdown hooks are what
# close the pg pools and call Redis QUIT rather than dropping in-flight commands, and they only run if
# the signal reaches node instead of a shell that swallows it.
CMD ["node", "dist/main.js"]
