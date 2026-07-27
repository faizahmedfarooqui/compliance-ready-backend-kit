#!/usr/bin/env bash
#
# Drop the tenant databases left behind by `pnpm smoke`.
#
# The smoke test provisions REAL databases, because provisioning a real database is one of the
# things it is there to prove. Two per run accumulate quickly on a dev machine.
#
# DRY RUN BY DEFAULT. Pass --yes to actually drop. It will only ever touch databases whose name
# matches one of the test prefixes below, and it refuses to run at all if a prefix is empty, so
# a typo cannot widen it to `tenant_%`.
#
# Local development only. Do not point this at anything you care about.
#
# Usage:
#   ./scripts/clean-test-tenants.sh          # list what would be dropped
#   ./scripts/clean-test-tenants.sh --yes    # drop them

set -euo pipefail

# Every prefix a test path is allowed to create. Keep in step with scripts/smoke-test.sh.
PREFIXES=(smoke- rc- shape- leakchk- e500)
CONTAINER="${POSTGRES_CONTAINER:-compliance-ready-backend-kit-postgres-1}"
APPLY=false
[ "${1:-}" = "--yes" ] && APPLY=true

for p in "${PREFIXES[@]}"; do
  if [ -z "$p" ]; then
    printf 'Refusing to run: an empty prefix would match every tenant database.\n' >&2
    exit 1
  fi
done

# `</dev/null` and no `-i` are both load-bearing. These run inside a `while read` loop, and a
# command that inherits stdin there consumes the rest of the loop's input: the first iteration
# succeeds, every later one is silently skipped, and the loop reports success. That bug dropped
# exactly one of 47 databases on the first run of this script.
psql_master() { docker exec "$CONTAINER" psql -U postgres -d master -t -A -c "$1" </dev/null; }
psql_admin() { docker exec "$CONTAINER" psql -U postgres -d postgres -q -c "$1" </dev/null; }
psql_admin_query() { docker exec "$CONTAINER" psql -U postgres -d postgres -t -A -c "$1" </dev/null; }

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  printf 'Container %s is not running. Start it with `pnpm infra:up`.\n' "$CONTAINER" >&2
  exit 1
fi

# Build a WHERE clause from the prefixes rather than interpolating a wildcard.
clause=""
for p in "${PREFIXES[@]}"; do
  [ -n "$clause" ] && clause="$clause OR "
  clause="${clause}slug LIKE '${p}%'"
done

# Databases are looked up from pg_database, NOT only from the tenant registry. A database can
# outlive its registry row: provisioning creates the database before marking the tenant active,
# so an interrupted run orphans one, and anything that deletes registry rows first leaves the
# databases behind. Scanning the cluster catches both.
db_clause=""
for p in "${PREFIXES[@]}"; do
  [ -n "$db_clause" ] && db_clause="$db_clause OR "
  # tenant slugs become database names with hyphens turned into underscores
  db_clause="${db_clause}datname LIKE 'tenant_$(printf '%s' "$p" | tr '-' '_')%'"
done

rows=$(psql_admin_query "SELECT datname FROM pg_database WHERE $db_clause ORDER BY datname" | grep . || true)
orphans=$(psql_master "SELECT count(*) FROM tenants WHERE $clause" | tr -d ' ')

if [ -z "$rows" ] && [ "${orphans:-0}" = "0" ]; then
  printf 'No test tenants found.\n'
  exit 0
fi

db_count=0
[ -n "$rows" ] && db_count=$(printf '%s\n' "$rows" | wc -l | tr -d ' ')
printf '%s test database(s), %s registry row(s):\n' "$db_count" "${orphans:-0}"
[ -n "$rows" ] && printf '%s\n' "$rows" | sed 's/^/  /'

if [ "$APPLY" != true ]; then
  printf '\nDry run. Re-run with --yes to drop these databases and registry rows.\n'
  exit 0
fi

printf '\n'
dropped=0
# Read the whole list into an array first. Iterating a pipeline while also running commands that
# talk to the container is how the stdin-consumption bug happened; an array has no stdin.
if [ -n "$rows" ]; then
  # Not `mapfile`/`readarray`: those are bash 4+, and macOS still ships bash 3.2, so they fail
  # with "command not found" on the most common developer machine for this project.
  targets=()
  while IFS= read -r line; do
    [ -n "$line" ] && targets+=("$line")
  done <<< "$rows"

  for db in "${targets[@]}"; do
    [ -z "$db" ] && continue
    # Guard again at the point of no return: the name must still match a test prefix.
    ok=false
    for p in "${PREFIXES[@]}"; do
      case "$db" in "tenant_$(printf '%s' "$p" | tr '-' '_')"*) ok=true ;; esac
    done
    if [ "$ok" != true ]; then
      printf '  SKIP %s (does not match a test prefix)\n' "$db"
      continue
    fi
    # WITH (FORCE) needs PG13+; fall back for older clusters.
    if psql_admin "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" >/dev/null 2>&1 \
      || psql_admin "DROP DATABASE IF EXISTS \"$db\"" >/dev/null 2>&1; then
      printf '  dropped %s\n' "$db"
      dropped=$((dropped + 1))
    else
      printf '  FAILED to drop %s\n' "$db" >&2
    fi
  done
fi

deleted=$(psql_master "WITH d AS (DELETE FROM tenants WHERE $clause RETURNING 1) SELECT count(*) FROM d" | tr -d ' ')
printf 'Dropped %s/%s database(s), removed %s registry row(s).\n' "$dropped" "$db_count" "$deleted"

remaining=$(psql_admin_query "SELECT count(*) FROM pg_database WHERE $db_clause" | tr -d ' ')
if [ "${remaining:-0}" != "0" ]; then
  printf 'WARNING: %s test database(s) still present.\n' "$remaining" >&2
  exit 1
fi
