import { readFileSync } from "node:fs";
import path from "node:path";
import { Controller, Get } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { NoRateLimit } from "../ratelimit/rate-limit.decorator";

/**
 * Liveness endpoint, and the answer to "which build am I actually talking to".
 *
 * That second job is not decoration. A stale server process holding the port will answer every
 * request happily, and a test suite pointed at it reports a pass for code that is not running.
 * This is what makes that visible: `startedAt` and `uptimeSeconds` expose a process that has
 * been up far longer than the build under test, and the smoke test asserts on it.
 *
 * Unauthenticated and tenant-free on purpose, so a load balancer or container orchestrator can
 * poll it. It therefore discloses only the service name, version, and uptime: nothing about
 * tenants, configuration, or dependencies.
 *
 * Deliberately does NOT touch the database. A liveness probe that fails when Postgres blips
 * gets the container killed and restarted, which fixes nothing and removes capacity during an
 * incident. A separate readiness probe that does check dependencies is on the roadmap.
 */
const STARTED_AT = new Date();

interface HealthReport {
  status: "ok";
  service: string;
  version: string;
  startedAt: string;
  uptimeSeconds: number;
}

/**
 * Read once at module load. Resolves from both `dist/` and `src/`, since `..` from either is
 * the service root.
 */
const PACKAGE = readPackage();

function readPackage(): { name: string; version: string } {
  try {
    const raw = readFileSync(path.resolve(__dirname, "..", "..", "package.json"), "utf8");
    const parsed = JSON.parse(raw) as { name?: string; version?: string };
    return { name: parsed.name ?? "unknown", version: parsed.version ?? "unknown" };
  } catch {
    // Never let a health endpoint be the reason a service fails to boot.
    return { name: "unknown", version: "unknown" };
  }
}

/**
 * Exempt from rate limiting, which is the case @NoRateLimit exists for. A load balancer or
 * orchestrator polls this on a fixed interval from a small number of addresses, so under load it is
 * exactly the caller most likely to exhaust a per-address budget. A 429 here reads as "unhealthy",
 * the instance is pulled from rotation, and the remaining instances absorb its traffic and start
 * failing their own health checks. Rate limiting the liveness probe converts load into an outage.
 */
@ApiTags("health")
@NoRateLimit()
@Controller("health")
export class HealthController {
  @ApiOperation({
    summary: "Liveness, and which build is actually running",
    description:
      "Unauthenticated, tenant-free, and exempt from rate limiting so a load balancer can poll it: a " +
      "429 here reads as unhealthy and would pull the instance from rotation, turning load into an " +
      "outage.\n\n" +
      "Deliberately does NOT touch the database. A liveness probe that fails when Postgres blips gets " +
      "the container killed, which fixes nothing and removes capacity during an incident.\n\n" +
      "`startedAt` and `uptimeSeconds` exist so a stale process holding the port is visible: it would " +
      "answer every request happily and a suite pointed at it would report a pass for code that is not " +
      "running. The smoke test asserts on them for that reason.",
  })
  @Get()
  check(): HealthReport {
    return {
      status: "ok",
      service: PACKAGE.name,
      version: PACKAGE.version,
      startedAt: STARTED_AT.toISOString(),
      uptimeSeconds: Math.floor((Date.now() - STARTED_AT.getTime()) / 1000),
    };
  }
}
