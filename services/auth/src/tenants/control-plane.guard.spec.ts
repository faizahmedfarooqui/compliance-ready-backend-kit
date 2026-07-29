import { describe, expect, it } from "vitest";
import type { ExecutionContext } from "@nestjs/common";
import { ControlPlaneUnauthorizedError } from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import { ControlPlaneGuard } from "./control-plane.guard";

/**
 * This guard is the only thing between the open internet and a route that creates databases, so the
 * cases below are less about the happy path than about the ways a credential check quietly stops
 * checking: an empty configured key matching an empty header, a prefix comparison accepting a
 * truncated key, a length mismatch throwing instead of rejecting.
 */

const KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function guard(configuredKey = KEY): ControlPlaneGuard {
  return new ControlPlaneGuard({ controlPlaneApiKey: configuredKey } as AppConfig);
}

/** A context carrying one Authorization header value. */
function context(authorization?: string | string[]): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        headers: authorization === undefined ? {} : { authorization },
        method: "POST",
        url: "/api/tenants",
        ip: "203.0.113.9",
      }),
    }),
  } as unknown as ExecutionContext;
}

describe("ControlPlaneGuard", () => {
  it("admits a request carrying the configured key", () => {
    expect(guard().canActivate(context(`Bearer ${KEY}`))).toBe(true);
  });

  // RFC 9110 s11.1 makes the scheme name case-insensitive, so a client sending "bearer" is correct.
  it("accepts the scheme in any case", () => {
    for (const scheme of ["Bearer", "bearer", "BEARER", "BeArEr"]) {
      expect(guard().canActivate(context(`${scheme} ${KEY}`))).toBe(true);
    }
  });

  it("tolerates surrounding whitespace and extra spaces after the scheme", () => {
    expect(guard().canActivate(context(`  Bearer   ${KEY}  `))).toBe(true);
  });

  describe("rejects", () => {
    it.each([
      ["no Authorization header", undefined],
      ["an empty header", ""],
      ["the key with no scheme", KEY],
      ["the wrong scheme", `Basic ${KEY}`],
      ["a scheme with no credential", "Bearer"],
      ["a scheme with only whitespace", "Bearer    "],
    ])("%s", (_label, header) => {
      expect(() => guard().canActivate(context(header))).toThrow(ControlPlaneUnauthorizedError);
    });

    it("a different key of the same length", () => {
      const other = `B${KEY.slice(1)}`;
      expect(() => guard().canActivate(context(`Bearer ${other}`))).toThrow(
        ControlPlaneUnauthorizedError,
      );
    });

    /**
     * A length mismatch must REJECT rather than throw something else. `timingSafeEqual` raises on
     * buffers of unequal length, so reaching it with a short or overlong credential would turn a 401
     * into a 500. The guard checks the length first, which is safe because the required length is
     * public: the config schema fixes it and .env.example publishes it.
     */
    it.each([
      ["a truncated key", KEY.slice(0, 10)],
      ["a single character", "A"],
      ["a key with extra characters appended", `${KEY}extra`],
      ["a very long value", "A".repeat(5000)],
    ])("%s, without throwing anything other than the domain error", (_label, presented) => {
      expect(() => guard().canActivate(context(`Bearer ${presented}`))).toThrow(
        ControlPlaneUnauthorizedError,
      );
    });

    /**
     * An array-valued header is refused rather than joined or picked from. Fastify hands back an array
     * when a header appears twice, so accepting one element would let a caller send a bad key alongside
     * a good one and have the pair treated as valid depending on read order.
     */
    it("a duplicated Authorization header", () => {
      expect(() => guard().canActivate(context([`Bearer ${KEY}`, "Bearer other"]))).toThrow(
        ControlPlaneUnauthorizedError,
      );
    });
  });

  /**
   * Every rejection is the same error with the same message. A prober must not be able to tell a
   * missing credential from a wrong one, or learn that their header shape was accepted.
   */
  it("gives one indistinguishable error for every kind of failure", () => {
    const messages = new Set<string>();
    for (const header of [undefined, "", KEY, `Basic ${KEY}`, "Bearer wrong", "Bearer"]) {
      try {
        guard().canActivate(context(header));
      } catch (err) {
        messages.add(err instanceof Error ? err.message : String(err));
      }
    }
    expect(messages.size).toBe(1);
  });

  /**
   * The configured key cannot be empty, because two empty buffers are equal length and compare equal,
   * which would open the route to a caller sending `Authorization: Bearer` with nothing after it. Config
   * enforces 256 bits so this state is unreachable in a running service; asserted here because the guard
   * is what would be exploited if that ever changed. Note the bearer parser also refuses a credential
   * that is only whitespace, so there are two independent reasons this cannot happen.
   */
  it("cannot be satisfied by an empty credential even if one were configured", () => {
    expect(() => guard("").canActivate(context("Bearer "))).toThrow(ControlPlaneUnauthorizedError);
    expect(() => guard("").canActivate(context("Bearer"))).toThrow(ControlPlaneUnauthorizedError);
    expect(() => guard("").canActivate(context(""))).toThrow(ControlPlaneUnauthorizedError);
  });
});
