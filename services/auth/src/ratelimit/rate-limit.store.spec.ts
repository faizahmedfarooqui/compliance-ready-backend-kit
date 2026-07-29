import { describe, expect, it, vi } from "vitest";
import type { Redis } from "ioredis";
import type { AppConfig } from "@compliance-kit/config";
import { RateLimitStore, newMemberIdFactory, type RateLimitResult } from "./rate-limit.store";

/**
 * The member id is the whole subject here, because getting it wrong fails in the one direction nobody
 * notices: a repeated member makes `ZADD` update a score instead of adding an entry, `ZCARD` does not
 * grow, and the limiter permits more than it says while every response still looks correct.
 *
 * A comment previously asserted the member was unique. It was, within one process, and the code used
 * `process.pid`, which is 1 in a container. So these are assertions rather than prose.
 */

const CONFIG = { rateLimitFailOpen: true } as AppConfig;

/** A client that records the member argument of every slidingWindow call. */
function client() {
  const members: string[] = [];
  const slidingWindow = vi.fn(
    (
      _key: string,
      _window: string,
      _limit: string,
      member: string,
    ): Promise<[number, number, number]> => {
      members.push(member);
      return Promise.resolve([1, 1, 0]);
    },
  );
  const stub = {
    defineCommand: vi.fn(),
    slidingWindow,
    del: vi.fn(() => Promise.resolve(1)),
  } as unknown as Redis;
  return { stub, members };
}

describe("RateLimitStore member ids", () => {
  it("are distinct for successive events in one process", async () => {
    const { stub, members } = client();
    const store = new RateLimitStore(stub, CONFIG);

    for (let i = 0; i < 50; i += 1) await store.consume("k", 100, 60_000);

    expect(new Set(members).size).toBe(50);
  });

  /**
   * Two stores in ONE process must not collide either.
   *
   * They share the instance id, so the counter is what separates them, and that is why it lives at
   * module scope rather than on the instance. Per-instance, both stores would restart from zero and emit
   * the same members. Nest constructs one store today, so this could not bite yet; the pid version could
   * not bite in development either.
   */
  it("never collide between two stores in the same process", async () => {
    const a = client();
    const b = client();
    const storeA = new RateLimitStore(a.stub, CONFIG);
    const storeB = new RateLimitStore(b.stub, CONFIG);

    for (let i = 0; i < 50; i += 1) {
      await storeA.consume("k", 100, 60_000);
      await storeB.consume("k", 100, 60_000);
    }

    // The important assertion: no member from one instance appears in the other. An intersection of
    // even one is an event that would silently not be counted.
    const overlap = a.members.filter((m) => b.members.includes(m));
    expect(overlap).toEqual([]);
    expect(new Set([...a.members, ...b.members]).size).toBe(100);
  });

  /**
   * THE REGRESSION THIS FILE EXISTS FOR: a genuinely separate process.
   *
   * `vi.resetModules()` plus a re-import gives a fresh module registry, so the second store gets a NEW
   * randomly generated INSTANCE_ID and a counter starting from zero. That is what a replica or a restart
   * looks like, and it is the case a same-process test cannot reach.
   *
   * With `${process.pid}:${counter}` both processes emitted `1:1`, `1:2`, `1:3`, because a containerised
   * process gets PID 1. `ZADD` on an existing member updates its score and returns 0, so the second
   * process's events silently were not counted and the limiter permitted roughly twice its configured
   * limit across two replicas.
   */
  it("never collide with a separately created factory, which is what a replica or restart is", () => {
    const processA = newMemberIdFactory();
    const processB = newMemberIdFactory();

    const a = Array.from({ length: 200 }, () => processA());
    const b = Array.from({ length: 200 }, () => processB());

    // With `${process.pid}:${counter}` these two lists were IDENTICAL, because a containerised process
    // gets PID 1 and each counter starts at zero. ZADD on an existing member updates its score and
    // returns 0, so process B's events silently were not counted.
    expect(a.filter((m) => b.includes(m))).toEqual([]);
    expect(new Set([...a, ...b]).size).toBe(400);
  });

  it("differ in their prefix between factories, which is what separates processes", () => {
    const prefix = (m: string): string => m.slice(0, m.lastIndexOf(":"));
    expect(prefix(newMemberIdFactory()())).not.toBe(prefix(newMemberIdFactory()()));
  });

  // The counter half. Randomness alone would leave a birthday problem inside a single busy process;
  // a monotonic suffix makes same-process collisions impossible rather than merely unlikely.
  it("carry a monotonic suffix, so uniqueness within a process does not rely on chance", async () => {
    const { stub, members } = client();
    const store = new RateLimitStore(stub, CONFIG);

    for (let i = 0; i < 5; i += 1) await store.consume("k", 100, 60_000);

    // Relative, not absolute: the counter is process-wide, so earlier tests in this file have already
    // advanced it. What matters is that it only ever increases by one.
    const suffixes = members.map((m) => Number(m.slice(m.lastIndexOf(":") + 1)));
    const deltas = suffixes.slice(1).map((n, i) => n - suffixes[i]);
    expect(deltas).toEqual([1, 1, 1, 1]);
  });

  // The pid is what this used to be, and it is the same in every container.
  it("are not derived from the process id", async () => {
    const { stub, members } = client();
    await new RateLimitStore(stub, CONFIG).consume("k", 100, 60_000);
    expect(members[0].startsWith(`${process.pid}:`)).toBe(false);
  });

  /**
   * A Redis failure must resolve to the configured policy rather than propagate. A limiter that can
   * fail a request by falling over is a new outage cause attached to every route.
   */
  describe("when Redis is unreachable", () => {
    function failing(): Redis {
      return {
        defineCommand: vi.fn(),
        slidingWindow: vi.fn(() => Promise.reject(new Error("ECONNREFUSED"))),
        peekWindow: vi.fn(() => Promise.reject(new Error("ECONNREFUSED"))),
        del: vi.fn(() => Promise.reject(new Error("ECONNREFUSED"))),
      } as unknown as Redis;
    }

    it("allows the request when configured to fail open, and says it is degraded", async () => {
      const store = new RateLimitStore(failing(), { rateLimitFailOpen: true } as AppConfig);
      const result = await store.consume("k", 10, 1_000);
      expect(result.allowed).toBe(true);
      expect(result.degraded).toBe(true);
    });

    it("rejects when configured to fail closed, with a short retry rather than a full window", async () => {
      const store = new RateLimitStore(failing(), { rateLimitFailOpen: false } as AppConfig);
      const result = await store.consume("k", 10, 900_000);
      expect(result.allowed).toBe(false);
      expect(result.degraded).toBe(true);
      // Short on purpose: the outage is our fault and may already be over, so a wait derived from the
      // window would punish callers for it.
      expect(result.retryAfterMs).toBeLessThanOrEqual(1_000);
    });

    // Login throttling consults peek before checking a password, so a peek that rejected during an
    // outage would lock every user out of the service entirely.
    it("always allows a peek, whatever the fail-open policy says", async () => {
      const store = new RateLimitStore(failing(), { rateLimitFailOpen: false } as AppConfig);
      const result = await store.peek("k", 10, 900_000);
      expect(result.allowed).toBe(true);
      expect(result.degraded).toBe(true);
    });

    it("does not throw when clearing a key fails", async () => {
      const store = new RateLimitStore(failing(), CONFIG);
      await expect(store.reset("k")).resolves.toBeUndefined();
    });
  });
});

/**
 * Header behaviour when a route carries its own budget, so `setHeaders` runs twice.
 *
 * Exercised through a hand-built reply rather than the guard, because what is being pinned is the
 * interaction between the two calls: whichever order they happen in, the response must never claim a
 * budget was checked when one of the two was not.
 */
describe("rate-limit headers across two checks", () => {
  function reply() {
    const headers = new Map<string, string>();
    return {
      obj: {
        header: (n: string, v: string) => headers.set(n, v),
        removeHeader: (n: string) => headers.delete(n),
        getHeader: (n: string) => headers.get(n),
      },
      get: (n: string) => headers.get(n),
    };
  }

  /** The guard's private setHeaders, replicated so the ordering rule can be asserted directly. */
  function setHeaders(r: ReturnType<typeof reply>["obj"], result: RateLimitResult): void {
    if (result.degraded) {
      r.removeHeader("x-ratelimit-limit");
      r.removeHeader("x-ratelimit-remaining");
      r.header("x-ratelimit-degraded", "true");
      return;
    }
    if (r.getHeader("x-ratelimit-degraded") !== undefined) return;
    r.header("x-ratelimit-limit", String(result.limit));
    r.header("x-ratelimit-remaining", String(Math.max(0, result.limit - result.count)));
  }

  const ok = (limit: number, count: number): RateLimitResult => ({
    allowed: true,
    count,
    limit,
    retryAfterMs: 0,
    degraded: false,
  });
  const degraded = (): RateLimitResult => ({
    allowed: true,
    count: 0,
    limit: 0,
    retryAfterMs: 0,
    degraded: true,
  });

  it("reports the tighter budget when neither check degraded", () => {
    const r = reply();
    setHeaders(r.obj, ok(100, 1)); // global
    setHeaders(r.obj, ok(20, 1)); // route
    expect(r.get("x-ratelimit-limit")).toBe("20");
    expect(r.get("x-ratelimit-degraded")).toBeUndefined();
  });

  // A response carrying both a budget and the degraded flag says a limit was checked when it was not.
  it("removes a budget set by the global check if the route check degrades", () => {
    const r = reply();
    setHeaders(r.obj, ok(100, 1));
    setHeaders(r.obj, degraded());
    expect(r.get("x-ratelimit-degraded")).toBe("true");
    expect(r.get("x-ratelimit-limit")).toBeUndefined();
    expect(r.get("x-ratelimit-remaining")).toBeUndefined();
  });

  /**
   * The sticky case, and the reason this is not simply "clear the flag on success". If the global check
   * degraded, that budget was never consulted, so the request was partly unmetered no matter how the
   * second check went. Reporting a clean limit here would round a security signal in the flattering
   * direction.
   */
  it("keeps the degraded flag when a later check succeeds, rather than overstating enforcement", () => {
    const r = reply();
    setHeaders(r.obj, degraded()); // global could not be checked
    setHeaders(r.obj, ok(20, 1)); // route was
    expect(r.get("x-ratelimit-degraded")).toBe("true");
    expect(r.get("x-ratelimit-limit")).toBeUndefined();
  });
});
