import { describe, expect, it } from "vitest";
import { rateLimitIdentity } from "./client-address";

/**
 * The property that matters is that an attacker holding one IPv6 /64 gets ONE budget, not 2^64 of
 * them, while two different /64s stay separate. The rest is making sure every way of writing the same
 * address lands in the same bucket, since each spelling that did not would be a free bucket too.
 */
describe("rateLimitIdentity", () => {
  it("leaves an IPv4 address as it is", () => {
    expect(rateLimitIdentity("203.0.113.7")).toBe("203.0.113.7");
  });

  it("buckets two addresses in the same IPv6 /64 together", () => {
    const a = rateLimitIdentity("2001:db8:1:2:aaaa:bbbb:cccc:dddd");
    const b = rateLimitIdentity("2001:db8:1:2::1");
    expect(a).toBe("2001:db8:1:2::/64");
    expect(b).toBe(a);
  });

  it("keeps different /64s apart", () => {
    expect(rateLimitIdentity("2001:db8:1:2::1")).not.toBe(rateLimitIdentity("2001:db8:1:3::1"));
  });

  it.each([
    ["full form with leading zeros", "2001:0db8:0001:0002:0000:0000:0000:0001"],
    ["compressed", "2001:db8:1:2::1"],
    ["upper case", "2001:DB8:1:2::1"],
    ["with a zone id", "2001:db8:1:2::1%eth0"],
    ["with an embedded dotted quad", "2001:db8:1:2::192.0.2.1"],
  ])("gives the same bucket for the %s spelling", (_label, address) => {
    expect(rateLimitIdentity(address)).toBe("2001:db8:1:2::/64");
  });

  it("handles compression at the start and in the prefix itself", () => {
    expect(rateLimitIdentity("::1")).toBe("0:0:0:0::/64");
    expect(rateLimitIdentity("2001:db8::1")).toBe("2001:db8:0:0::/64");
  });

  // Every spelling of one IPv4-mapped address. Only the first used to be recognised, and the rest
  // collapsed into the single 0:0:0:0::/64 bucket, so all IPv4 clients of such a proxy shared one budget.
  it.each([
    ["dotted, compressed", "::ffff:203.0.113.7"],
    ["dotted, upper case", "::FFFF:203.0.113.7"],
    ["hexadecimal, compressed", "::ffff:cb00:7107"],
    ["hexadecimal, upper case", "::FFFF:CB00:7107"],
    ["dotted, uncompressed", "0:0:0:0:0:ffff:203.0.113.7"],
    ["hexadecimal, uncompressed", "0:0:0:0:0:ffff:cb00:7107"],
    ["hexadecimal, leading zeros", "0000:0000:0000:0000:0000:ffff:cb00:7107"],
    ["partially compressed", "0:0::ffff:cb00:7107"],
  ])("folds an IPv4-mapped address written %s back to IPv4", (_label, address) => {
    expect(rateLimitIdentity(address)).toBe("203.0.113.7");
  });

  it("keeps two different IPv4-mapped clients apart", () => {
    expect(rateLimitIdentity("::ffff:cb00:7107")).not.toBe(rateLimitIdentity("::ffff:cb00:7108"));
  });

  it("does not fold an address that only looks mapped", () => {
    expect(rateLimitIdentity("::fffe:cb00:7107")).toBe("0:0:0:0::/64");
  });

  it("returns anything that is not an IP address unchanged", () => {
    expect(rateLimitIdentity("unknown")).toBe("unknown");
  });
});
