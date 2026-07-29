import { describe, expect, it, vi } from "vitest";
import { TooManyRequestsError } from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import type { RateLimitStore, RateLimitResult } from "../ratelimit/rate-limit.store";
import { LoginThrottleService } from "./login-throttle.service";

/**
 * The behaviours here are the ones that are easy to get subtly wrong and impossible to notice: a
 * throttle that counts the wrong events still returns 429 sometimes, so it looks like it works.
 */

const CONFIG = { loginThrottleLimit: 10, loginThrottleWindowMs: 900_000 } as AppConfig;

const TENANT = "22222222-2222-4222-8222-222222222222";
const EMAIL = "admin@example.test";
const IP = "203.0.113.7";

function result(over: Partial<RateLimitResult> = {}): RateLimitResult {
  return { allowed: true, count: 0, limit: 10, retryAfterMs: 0, degraded: false, ...over };
}

/** A store whose answers are scripted per key, so each counter can be driven independently. */
function store(answers: Record<string, RateLimitResult> = {}) {
  const peek = vi.fn((key: string) => {
    const match = Object.keys(answers).find((k) => key.includes(k));
    return Promise.resolve(match ? answers[match] : result());
  });
  // Parameters are declared so the recorded call arguments are typed; an inferred `() => ...` mock
  // gives an empty tuple and `calls[0][0]` will not compile.
  const consume = vi.fn((_key: string, _limit?: number, _windowMs?: number) =>
    Promise.resolve(result()),
  );
  const reset = vi.fn((_key: string) => Promise.resolve());
  return {
    stub: { peek, consume, reset } as unknown as RateLimitStore,
    peek,
    consume,
    reset,
  };
}

describe("LoginThrottleService", () => {
  it("allows an attempt while both counters are under their limits", async () => {
    const { stub } = store();
    const throttle = new LoginThrottleService(stub, CONFIG);
    await expect(throttle.assertWithinLimits(TENANT, EMAIL, IP)).resolves.toBeUndefined();
  });

  it("throttles when the ACCOUNT counter is exhausted, whatever the address has done", async () => {
    const { stub } = store({
      "login:acct:": result({ allowed: false, count: 10, retryAfterMs: 5000 }),
    });
    const throttle = new LoginThrottleService(stub, CONFIG);
    await expect(throttle.assertWithinLimits(TENANT, EMAIL, IP)).rejects.toThrow(
      TooManyRequestsError,
    );
  });

  // The distributed case: many addresses against one account is stopped by the account counter, and one
  // address against many accounts is stopped by this one. Neither alone is sufficient.
  it("throttles when the ADDRESS counter is exhausted, even on an untouched account", async () => {
    const { stub } = store({
      "login:addr:": result({ allowed: false, count: 10, retryAfterMs: 9000 }),
    });
    const throttle = new LoginThrottleService(stub, CONFIG);
    await expect(throttle.assertWithinLimits(TENANT, EMAIL, IP)).rejects.toThrow(
      TooManyRequestsError,
    );
  });

  // Reporting the shorter wait would invite a caller to return while the other counter still rejects
  // them, so they would burn an attempt and be told to wait again.
  it("reports the LONGER of the two waits", async () => {
    const { stub } = store({
      "login:acct:": result({ allowed: false, retryAfterMs: 4_000 }),
      "login:addr:": result({ allowed: false, retryAfterMs: 30_000 }),
    });
    const throttle = new LoginThrottleService(stub, CONFIG);
    await expect(throttle.assertWithinLimits(TENANT, EMAIL, IP)).rejects.toMatchObject({
      retryAfterSeconds: 30,
    });
  });

  /**
   * The response must not distinguish "this account is throttled" from "this address is throttled".
   * The first would confirm that the account exists, which is the same disclosure
   * InvalidCredentialsError exists to avoid, and it would tell an attacker their target is real.
   */
  it("says nothing about which counter tripped", async () => {
    const { stub } = store({ "login:acct:": result({ allowed: false, count: 10 }) });
    const throttle = new LoginThrottleService(stub, CONFIG);
    await expect(throttle.assertWithinLimits(TENANT, EMAIL, IP)).rejects.toThrow(
      /^Too many requests\. Retry later\.$/,
    );
  });

  describe("counting", () => {
    it("charges a failure to both the account and the address", async () => {
      const { stub, consume } = store();
      const throttle = new LoginThrottleService(stub, CONFIG);
      await throttle.recordFailure(TENANT, EMAIL, IP);

      const keys = consume.mock.calls.map((c) => String(c[0]));
      expect(keys.some((k) => k.startsWith("login:acct:"))).toBe(true);
      expect(keys.some((k) => k.startsWith("login:addr:"))).toBe(true);
    });

    /**
     * The asymmetry that matters. Clearing the address counter on success would hand anyone holding one
     * valid account a reset button: fail against nine others, log in to their own, repeat forever.
     * Spraying is what the address counter is for, so it has to survive a success.
     */
    it("clears the account counter on success and leaves the address counter alone", async () => {
      const { stub, reset } = store();
      const throttle = new LoginThrottleService(stub, CONFIG);
      await throttle.recordSuccess(TENANT, EMAIL);

      const keys = reset.mock.calls.map((c) => String(c[0]));
      expect(keys.some((k) => k.startsWith("login:acct:"))).toBe(true);
      expect(keys.some((k) => k.startsWith("login:addr:"))).toBe(false);
    });
  });

  describe("account keys", () => {
    it("do not contain the email address", async () => {
      const { stub, consume } = store();
      const throttle = new LoginThrottleService(stub, CONFIG);
      await throttle.recordFailure(TENANT, EMAIL, IP);

      const accountKey = consume.mock.calls
        .map((c) => String(c[0]))
        .find((k) => k.startsWith("login:acct:"));
      expect(accountKey).toBeDefined();
      expect(accountKey).not.toContain(EMAIL);
      expect(accountKey).not.toContain("admin");
      expect(accountKey).not.toContain("example.test");
    });

    // The same address in two tenants is two accounts. A shared bucket would let failures in one
    // tenant throttle a different user in another, which is a cross-tenant effect.
    it("differ per tenant for the same address", async () => {
      const keyFor = async (tenant: string): Promise<string> => {
        const { stub, consume } = store();
        await new LoginThrottleService(stub, CONFIG).recordFailure(tenant, EMAIL, IP);
        return String(
          consume.mock.calls.map((c) => String(c[0])).find((k) => k.startsWith("login:acct:")),
        );
      };
      expect(await keyFor(TENANT)).not.toBe(await keyFor("33333333-3333-4333-8333-333333333333"));
    });

    // Same normalisation as the user table, or "Admin@x" and "admin@x" would be two budgets for one
    // account and the limit would be twice what it says.
    it("ignore case and surrounding whitespace, matching how accounts are stored", async () => {
      const keyFor = async (email: string): Promise<string> => {
        const { stub, consume } = store();
        await new LoginThrottleService(stub, CONFIG).recordFailure(TENANT, email, IP);
        return String(
          consume.mock.calls.map((c) => String(c[0])).find((k) => k.startsWith("login:acct:")),
        );
      };
      expect(await keyFor("  ADMIN@Example.TEST ")).toBe(await keyFor(EMAIL));
    });
  });
});

/**
 * Retry-After is a header value, so its type is not a detail. RFC 9110 s10.2.3 defines delay-seconds
 * as a non-negative integer.
 */
describe("TooManyRequestsError retry hint", () => {
  it("rounds up, so a sub-second wait never serialises as an immediate retry", () => {
    expect(new TooManyRequestsError(1).retryAfterSeconds).toBe(1);
    expect(new TooManyRequestsError(1_400).retryAfterSeconds).toBe(2);
  });

  it("floors at 1 even for zero or a negative input", () => {
    expect(new TooManyRequestsError(0).retryAfterSeconds).toBe(1);
    expect(new TooManyRequestsError(-5_000).retryAfterSeconds).toBe(1);
  });

  it("is always an integer", () => {
    for (const ms of [1, 999, 1_001, 59_999, 900_000]) {
      expect(Number.isInteger(new TooManyRequestsError(ms).retryAfterSeconds)).toBe(true);
    }
  });
});
