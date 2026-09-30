import { describe, expect, it } from "vitest";
import { singleAuthorizationHeader } from "./authorization-header";

/**
 * Requests here are shaped the way Node really delivers them. A repeated Authorization header is NOT
 * an array: the parsed `headers.authorization` holds the first value only, and the raw header list
 * holds every line as sent. Checked on Node 24 by sending two lines to a plain http server.
 */
function request(lines: string[]) {
  const headers: Record<string, string> = {};
  for (let i = 0; i < lines.length; i += 2) {
    const name = lines[i].toLowerCase();
    // First one wins, as Node's own parser does for authorization.
    if (!(name in headers)) headers[name] = lines[i + 1];
  }
  return { headers, raw: { rawHeaders: lines } };
}

describe("singleAuthorizationHeader", () => {
  it("returns the header when it appears exactly once", () => {
    expect(singleAuthorizationHeader(request(["Authorization", "Bearer abc"]))).toBe("Bearer abc");
  });

  it("returns undefined when there is no Authorization header", () => {
    expect(singleAuthorizationHeader(request(["Accept", "application/json"]))).toBeUndefined();
  });

  it("refuses two Authorization headers even though the parsed one looks fine", () => {
    const req = request(["Authorization", "Bearer first", "Authorization", "Bearer second"]);
    // The trap, stated as an assertion: Node's parsed view shows one ordinary credential.
    expect(req.headers.authorization).toBe("Bearer first");
    expect(singleAuthorizationHeader(req)).toBeUndefined();
  });

  it("counts header names case-insensitively, as HTTP defines them", () => {
    const req = request(["authorization", "Bearer first", "AUTHORIZATION", "Bearer second"]);
    expect(singleAuthorizationHeader(req)).toBeUndefined();
  });

  it("is not confused by other headers that merely contain the word", () => {
    const req = request([
      "Authorization",
      "Bearer abc",
      "Proxy-Authorization",
      "Basic xyz",
      "X-Authorization-Note",
      "unrelated",
    ]);
    expect(singleAuthorizationHeader(req)).toBe("Bearer abc");
  });

  it("falls back to the parsed header when there is no raw request to consult", () => {
    expect(singleAuthorizationHeader({ headers: { authorization: "Bearer abc" } })).toBe(
      "Bearer abc",
    );
    expect(singleAuthorizationHeader({ headers: {} })).toBeUndefined();
  });
});
