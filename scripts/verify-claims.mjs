#!/usr/bin/env node
/**
 * `pnpm verify:claims`: reproduce the evidence behind every control COMPLIANCE.md marks Implemented,
 * and report it BY CONTROL with its citation.
 *
 * WHO THIS IS FOR, because it decides the shape of everything below. The audience is someone
 * evaluating the kit who wants to know whether a row in COMPLIANCE.md is true. That is a different
 * question from the one a test suite answers. `pnpm test` says "267 tests pass", which is a fact
 * about this repository's diligence and not an answer to "is multi-tenant isolation real". So the
 * output is grouped by control, each with the HIPAA / PCI / SOC 2 citation it claims to support,
 * and the assertions are quoted back in the words they were written in.
 *
 * IT RE-IMPLEMENTS NOTHING, and that is the central design rule. Every assertion already lives in
 * scripts/smoke-test.sh, scripts/slowloris-probe.mjs, the two audit probes, or the unit suite. This
 * script runs those and attributes their output. A copy of an assertion here would be a second
 * source of truth that can drift from the real one while still printing PASS, which is precisely
 * the failure mode a compliance document cannot afford.
 *
 * Attribution therefore works by matching a substring against a PASSING line of a suite's output.
 * That makes the registry below deliberately brittle: rename an assertion and the match stops
 * resolving. That is the correct behaviour, and it is reported as MISSING rather than as a failure,
 * because "the evidence moved" and "the control broke" are different problems and conflating them
 * would hide both.
 *
 * TWO MODES:
 *
 *   pnpm verify:claims             run the suites and report per control. Needs live infrastructure.
 *   pnpm verify:claims --coverage  static. Fails if a row marked Implemented has no registered
 *                                  evidence, or if the registry names a row that no longer exists.
 *
 * The coverage mode is the one CI runs on every pull request, and it is the point of the exercise:
 * it turns the project's anti-overclaim rule from a habit that holds while someone remembers it into
 * something the build enforces. Marking a row Implemented without wiring up evidence now fails.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const COMPLIANCE_PATH = join(REPO_ROOT, "COMPLIANCE.md");

/**
 * The suites that hold the evidence.
 *
 * `passMarker` is how each one spells a passing line: the bash suite and both probes print `PASS`,
 * vitest prints a check mark. A match counts only when the line carries that marker, so a substring
 * appearing in a FAIL line, or in a comment echoed to stdout, cannot be mistaken for evidence.
 */
const SUITES = {
  smoke: {
    label: "pnpm smoke",
    command: "pnpm",
    args: ["smoke"],
    passMarker: "PASS",
    needs:
      "a running auth-service plus Postgres and Redis, and CONTROL_PLANE_API_KEY exported in the " +
      "shell (not only in .env, because CI has no .env)",
  },
  slowloris: {
    label: "pnpm smoke:slowloris",
    command: "pnpm",
    args: ["smoke:slowloris"],
    passMarker: "PASS",
    needs: "a running auth-service, and it takes as long as the configured request timeout",
  },
  immutability: {
    label: "pnpm audit:immutability --master",
    command: "pnpm",
    args: ["audit:immutability", "--master"],
    passMarker: "PASS",
    needs: "Postgres, and a NON-EMPTY audit chain: run pnpm smoke first, or the probe exits 1",
  },
  contention: {
    label: "pnpm audit:contention",
    command: "pnpm",
    args: ["audit:contention"],
    passMarker: "PASS",
    needs: "Postgres",
  },
  unit: {
    label: "pnpm vitest run",
    command: "pnpm",
    args: ["vitest", "run", "--reporter=verbose"],
    passMarker: "✓",
    needs: "nothing beyond the workspace",
  },
  audit: {
    label: "pnpm audit --audit-level=high",
    command: "pnpm",
    args: ["audit", "--audit-level=high"],
    // This one is judged by exit code rather than by a passing line, because a clean audit prints
    // "No known vulnerabilities found" and nothing resembling a per-check result.
    exitCodeOnly: true,
    needs: "the network, to reach the advisory database",
  },
};

/**
 * The order suites run in, which is not arbitrary.
 *
 * `smoke` MUST come before `immutability`: the probe refuses to run against an empty chain and exits
 * 1, because row triggers are FOR EACH ROW, so on an empty table an UPDATE matches nothing, succeeds,
 * and the check would pass against a table with no protection whatsoever. Smoke is what puts events
 * in the chain for it to fire on.
 *
 * Every suite referenced by the registry must appear here or it never runs; validateRegistry() below
 * enforces that rather than trusting it.
 */
const RUN_ORDER = ["smoke", "slowloris", "immutability", "contention", "unit", "audit"];

/**
 * Control -> the evidence that supports it.
 *
 * Keys MUST match a Capability cell in COMPLIANCE.md exactly; the coverage gate checks that in both
 * directions, so a renamed row fails the build rather than silently losing its evidence.
 *
 * Rows that are Partial or Not implemented are allowed to appear here and are allowed to be absent.
 * Only Implemented rows are required to have evidence, because that is the claim being audited.
 */
const EVIDENCE = {
  "Multi-tenant isolation (database-per-tenant)": [
    { suite: "smoke", match: "tenant B sees none of tenant A's users" },
    { suite: "smoke", match: "tenant B holds exactly its own 1 user while tenant A holds 2" },
    { suite: "smoke", match: "GET /users with a token minted for a different tenant" },
    { suite: "smoke", match: "rejected with CROSS_TENANT_TOKEN" },
    { suite: "smoke", match: "GET /users with an unknown tenant slug" },
  ],

  "RBAC / access control": [
    { suite: "smoke", match: "GET /users as tenant-admin" },
    { suite: "smoke", match: "GET /users without the users:read permission" },
    { suite: "smoke", match: "registered user's token carries no permissions" },
    { suite: "smoke", match: "permissions claim carries the seeded grants" },
    { suite: "unit", match: "services/auth/src/rbac/permissions.guard.spec.ts" },
  ],

  "Password storage (Argon2id KDF)": [
    { suite: "unit", match: "uses argon2id, not argon2i or argon2d" },
    {
      suite: "unit",
      match: "states the cost parameters explicitly rather than inheriting library defaults",
    },
    { suite: "unit", match: "encodes the chosen parameters into the digest" },
    { suite: "smoke", match: "POST /auth/login with a wrong password" },
    { suite: "smoke", match: "POST /auth/login for a nonexistent user" },
  ],

  "Access-token confidentiality (nested JWT: signed, then encrypted)": [
    { suite: "smoke", match: "token is a 5-segment compact JWE (not a bare 3-segment JWS)" },
    { suite: "smoke", match: "no segment of the token reveals claims without the encryption key" },
    { suite: "smoke", match: "outer JWE is A256KW + A256GCM" },
    { suite: "smoke", match: "explicitly typed crbk-at+jwt" },
    { suite: "smoke", match: "outer header names its key with a kid" },
    { suite: "unit", match: "signs with ES256, not HS256" },
    { suite: "unit", match: "a valid JWE wrapping a FORGED inner signature" },
    { suite: "unit", match: "a bare JWS that was never encrypted" },
    { suite: "unit", match: "rejects a token naming an unknown encryption kid" },
    { suite: "unit", match: "leaks no claim into the outer header, which is not encrypted" },
  ],

  "Input validation": [
    { suite: "smoke", match: "unknown properties are rejected, not ignored" },
    { suite: "smoke", match: "each field problem carries a JSON Pointer (#/slug)" },
    { suite: "smoke", match: "invalid field values give 422, not 400" },
    { suite: "smoke", match: "unparseable body gives 400, distinct from 422" },
    { suite: "unit", match: "services/auth/src/common/validation-exception.factory.spec.ts" },
  ],

  "Append-only audit logging (hash-chained)": [
    // The three refusals are the control's central claim, and they were the last claim in the kit
    // with no runnable evidence: before the probe existed they had only been checked by hand.
    { suite: "immutability", match: "refused by the trigger" },
    { suite: "immutability", match: "a duplicate prev_hash is refused by" },
    { suite: "immutability", match: "nothing was destroyed" },
    { suite: "immutability", match: "append still works" },
    { suite: "contention", match: "so the lock serialised them" },
    { suite: "contention", match: "one unbroken chain, no fork" },
    { suite: "smoke", match: "audit chain verifies from genesis to head" },
    { suite: "smoke", match: "the control-plane chain verifies" },
    { suite: "smoke", match: "verify prints a 64-hex head hash" },
    { suite: "unit", match: "packages/crypto/src/audit-hash.spec.ts" },
  ],

  "Rate limiting and login throttling (application layer)": [
    {
      suite: "smoke",
      match: "the rejected call was rate limited too, so the limiter runs before authentication",
    },
    { suite: "unit", match: "services/auth/src/ratelimit/rate-limit.store.spec.ts" },
    { suite: "unit", match: "services/auth/src/auth/login-throttle.service.spec.ts" },
    { suite: "unit", match: "says nothing about which counter tripped" },
  ],

  "Request-level DoS limits (timeouts, body size)": [
    // Asserts a 408 at roughly the configured timeout rather than accepting any quick response,
    // which is the difference between proving the timeout and proving the server is reachable.
    { suite: "slowloris", match: "server answered 408" },
  ],

  "Control-plane authorization (tenant provisioning)": [
    { suite: "smoke", match: "POST /tenants with NO credential" },
    { suite: "smoke", match: "POST /tenants with a WRONG credential" },
    { suite: "smoke", match: "POST /tenants with the key but no Bearer scheme" },
    { suite: "smoke", match: "rejection carries the CONTROL_PLANE_UNAUTHORIZED code" },
    { suite: "smoke", match: "the rejected tenant was never created" },
    { suite: "unit", match: "services/auth/src/tenants/control-plane.guard.spec.ts" },
  ],

  // A Partial row, included because the part that DOES exist is runnable and worth showing. What is
  // still missing (an SBOM, a documented 12-month cryptographic inventory review) is why the row is
  // not Implemented, and no amount of passing evidence here should be read as closing that gap.
  "Vulnerability / dependency management": [{ suite: "audit" }],
};

const GREEN = "[32m";
const RED = "[31m";
const YELLOW = "[33m";
const DIM = "[2m";
const BOLD = "[1m";
const RESET = "[0m";

/**
 * Parse the control table out of COMPLIANCE.md.
 *
 * Reading the document rather than duplicating its contents is the whole point: the gate has to fail
 * when the DOCUMENT changes, so the document must be the input.
 */
function parseComplianceTable(markdown) {
  const rows = [];
  let inTable = false;

  for (const line of markdown.split("\n")) {
    if (line.startsWith("| Capability")) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    if (!line.startsWith("|")) break;
    if (/^\|\s*-{3}/.test(line)) continue;

    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 5) continue;

    rows.push({
      capability: cells[0],
      status: cells[1].replace(/\*\*/g, "").trim(),
      hipaa: cells[2],
      pci: cells[3],
      soc2: cells[4],
    });
  }

  return rows;
}

/** The anti-overclaim rule, executable. Needs no infrastructure, so CI runs it on every PR. */
function runCoverageGate(rows) {
  const problems = [];
  const capabilities = new Set(rows.map((r) => r.capability));

  for (const row of rows) {
    const evidence = EVIDENCE[row.capability];
    if (row.status === "Implemented" && (!evidence || evidence.length === 0)) {
      problems.push(
        `"${row.capability}" is marked Implemented but has no registered evidence. Either wire up ` +
          `the assertions that prove it, or change the status.`,
      );
    }
  }

  for (const key of Object.keys(EVIDENCE)) {
    if (!capabilities.has(key)) {
      problems.push(
        `the registry names "${key}", which is not a Capability in COMPLIANCE.md. It was probably ` +
          `renamed; update scripts/verify-claims.mjs to match.`,
      );
    }
  }

  const implemented = rows.filter((r) => r.status === "Implemented");
  const counts = rows.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1;
    return acc;
  }, {});

  console.log(`${BOLD}Evidence coverage for COMPLIANCE.md${RESET}\n`);
  console.log(`  ${rows.length} controls: ${JSON.stringify(counts)}`);
  console.log(`  ${implemented.length} marked Implemented, all of which must carry evidence.\n`);

  for (const row of implemented) {
    const n = EVIDENCE[row.capability]?.length ?? 0;
    const mark = n > 0 ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
    console.log(`  ${mark}  ${row.capability} ${DIM}(${n} evidence item(s))${RESET}`);
  }

  // Print the split rather than only a grand total, because the two numbers mean different things and
  // conflating them is a small overclaim of exactly the kind this script exists to prevent: evidence
  // attached to a Partial row is not evidence for an Implemented one. Review caught the docs doing
  // precisely that, so the authoritative counts are printed here for anyone updating prose.
  const implementedItems = implemented.reduce(
    (n, r) => n + (EVIDENCE[r.capability]?.length ?? 0),
    0,
  );
  const allItems = Object.values(EVIDENCE).reduce((n, items) => n + items.length, 0);
  console.log(
    `\n  ${implementedItems} evidence item(s) across the ${implemented.length} Implemented rows, ` +
      `${allItems - implementedItems} on rows with another status, ${allItems} in total.`,
  );

  const extra = Object.keys(EVIDENCE).filter(
    (k) => rows.find((r) => r.capability === k)?.status !== "Implemented",
  );
  if (extra.length > 0) {
    console.log(
      `\n  ${DIM}Also registered, though not required to be, because their status is not ` +
        `Implemented:${RESET}`,
    );
    for (const k of extra) console.log(`  ${DIM}  - ${k}${RESET}`);
  }

  if (problems.length > 0) {
    console.error(`\n${RED}${BOLD}Coverage gate failed.${RESET}`);
    for (const p of problems) console.error(`  - ${p}`);
    return 1;
  }

  console.log(`\n${GREEN}Every control marked Implemented has registered evidence.${RESET}`);
  return 0;
}

function runSuite(id) {
  const suite = SUITES[id];
  process.stdout.write(`  running ${suite.label} ... `);

  const result = spawnSync(suite.command, suite.args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    // Both streams, because the probes report failures on stderr and a partial run still carries
    // usable evidence for the checks that did pass.
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env,
  });

  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  const ok = result.status === 0;
  console.log(ok ? `${GREEN}exit 0${RESET}` : `${RED}exit ${String(result.status)}${RESET}`);

  return { ok, output, lines: output.split("\n") };
}

/**
 * Fail before running anything if the registry and the suites disagree.
 *
 * Both ways of getting this wrong are silent until they are not. A typo in a suite id, or a suite
 * added to SUITES and to the registry but forgotten in RUN_ORDER, would otherwise surface as a
 * TypeError on `suite.exitCodeOnly` or `run.lines` AFTER every suite had already been executed: a
 * stack trace at the end of a multi-minute run, naming a property instead of the mistake.
 */
function validateRegistry(needed) {
  const unknown = [...needed].filter((id) => !SUITES[id]);
  const unordered = [...needed].filter((id) => SUITES[id] && !RUN_ORDER.includes(id));
  if (unknown.length === 0 && unordered.length === 0) return true;

  console.error(`${RED}${BOLD}The evidence registry does not match the suites.${RESET}`);
  for (const id of unknown) {
    console.error(`  - "${id}" is referenced as a suite but is not defined in SUITES.`);
  }
  for (const id of unordered) {
    console.error(`  - "${id}" is defined in SUITES but missing from RUN_ORDER, so it never runs.`);
  }
  return false;
}

/** One evidence item against one suite's captured output. Returns "pass", "fail" or "missing". */
function judge(item, run) {
  const suite = SUITES[item.suite];

  if (suite.exitCodeOnly) {
    if (run.ok) {
      console.log(`  ${GREEN}PASS${RESET}  ${suite.label} ${DIM}(exit 0)${RESET}`);
      return "pass";
    }
    console.log(`  ${RED}FAIL${RESET}  ${suite.label} ${DIM}(non-zero exit)${RESET}`);
    return "fail";
  }

  if (run.lines.some((l) => l.includes(suite.passMarker) && l.includes(item.match))) {
    console.log(`  ${GREEN}PASS${RESET}  ${DIM}${item.suite}:${RESET} ${item.match}`);
    return "pass";
  }

  // The text appearing nowhere at all usually means the assertion was renamed rather than that it
  // failed. Reported separately so a stale registry cannot be mistaken for a broken control, or
  // the other way round.
  if (!run.output.includes(item.match)) {
    console.log(
      `  ${YELLOW}MISSING${RESET}  ${DIM}${item.suite}:${RESET} ${item.match} ` +
        `${DIM}(not found in the output; renamed?)${RESET}`,
    );
    return "missing";
  }

  console.log(`  ${RED}FAIL${RESET}  ${DIM}${item.suite}:${RESET} ${item.match}`);
  return "fail";
}

function runFull(rows) {
  const needed = new Set();
  for (const items of Object.values(EVIDENCE)) {
    for (const item of items) needed.add(item.suite);
  }
  if (!validateRegistry(needed)) return 1;

  console.log(`${BOLD}Reproducing the evidence behind COMPLIANCE.md${RESET}\n`);
  console.log(`${DIM}Each suite runs once; results are attributed to the controls they support.`);
  console.log(
    `Nothing here re-implements an assertion, so what you see is the real suite.${RESET}\n`,
  );

  const results = {};
  for (const id of RUN_ORDER) {
    if (needed.has(id)) results[id] = runSuite(id);
  }

  const tally = { pass: 0, fail: 0, missing: 0 };

  for (const row of rows) {
    const items = EVIDENCE[row.capability];
    if (!items || items.length === 0) continue;

    console.log(`\n${BOLD}${row.capability}${RESET}  ${DIM}[${row.status}]${RESET}`);
    console.log(`  ${DIM}HIPAA ${row.hipaa} | PCI-DSS ${row.pci} | SOC 2 ${row.soc2}${RESET}`);

    for (const item of items) tally[judge(item, results[item.suite])] += 1;
  }

  const { pass: passed, fail: failed, missing } = tally;
  console.log(`\n${BOLD}Summary${RESET}`);
  console.log(`  ${passed} passed, ${failed} failed, ${missing} missing`);

  if (failed > 0) {
    console.error(
      `\n${RED}${BOLD}A claim in COMPLIANCE.md is not supported by its evidence.${RESET}`,
    );
    return 1;
  }
  if (missing > 0) {
    console.error(
      `\n${YELLOW}${BOLD}Evidence could not be located.${RESET} The controls may well be fine; the ` +
        `registry in this script is probably stale. Fix the match strings.`,
    );
    return 1;
  }

  console.log(`\n${GREEN}Every registered claim reproduced.${RESET}`);
  return 0;
}

function main() {
  if (!existsSync(COMPLIANCE_PATH)) {
    console.error(`Cannot find ${COMPLIANCE_PATH}`);
    return 1;
  }

  const rows = parseComplianceTable(readFileSync(COMPLIANCE_PATH, "utf8"));
  if (rows.length === 0) {
    console.error(
      "Parsed no controls out of COMPLIANCE.md. The table header changed, or the table moved.",
    );
    return 1;
  }

  const args = process.argv.slice(2);
  if (args.includes("--coverage")) return runCoverageGate(rows);

  if (args.includes("--list")) {
    for (const row of rows) {
      const n = EVIDENCE[row.capability]?.length ?? 0;
      console.log(`${row.status.padEnd(22)} ${String(n).padStart(2)}  ${row.capability}`);
    }
    return 0;
  }

  console.log(`${DIM}Preconditions, because every one of these runs for real:${RESET}`);
  for (const id of Object.keys(SUITES)) {
    console.log(`${DIM}  ${SUITES[id].label}: ${SUITES[id].needs}${RESET}`);
  }
  console.log("");

  return runFull(rows);
}

process.exit(main());
