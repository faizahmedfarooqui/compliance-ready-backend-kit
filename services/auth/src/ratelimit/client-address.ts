import { isIPv4, isIPv6 } from "node:net";

/**
 * The identity a per-address limit counts against: the address for IPv4, the /64 for IPv6.
 *
 * Keying on the full IPv6 address would make every per-address limit in the kit optional. A single
 * IPv6 host is routinely handed a whole /64, so the last 64 bits cost an attacker nothing to rotate:
 * with the full address as the key, every request can arrive from a fresh address and draw a fresh
 * budget, against the client-wide limit, the per-route limits, and the per-address login counter whose
 * whole purpose is stopping one source spraying passwords across many accounts. The /64 is the smallest
 * block one party cannot be assumed to share, which is why it is the usual granularity for limiting
 * IPv6. The per-account login counter does not depend on this and was never affected.
 *
 * This only reaches the kit behind a proxy with TRUST_PROXY set, since the service listens on IPv4.
 * That is the production shape, and the reason it matters.
 *
 * An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) is folded back to plain IPv4, so one client is not
 * counted in two buckets depending on which socket family a proxy used to reach us. Anything that is
 * not an IP address (the guard's shared "unknown" fallback) is returned unchanged.
 *
 * For limiter keys only. Audit events keep the full address, because evidence should say what arrived.
 */
export function rateLimitIdentity(address: string): string {
  if (isIPv4(address)) return address;
  if (!isIPv6(address)) return address;

  const groups = expandIPv6(address.split("%")[0]);

  // IPv4-mapped (::ffff:0:0/96), recognised by value rather than by spelling. `::ffff:203.0.113.7`,
  // `::ffff:cb00:7107` and `0:0:0:0:0:ffff:203.0.113.7` are one address; matching only the first
  // form used to put every IPv4 client of a proxy that writes the others into the single
  // `0:0:0:0::/64` bucket, so the busiest one throttled all of them.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join(".");
  }

  return `${groups
    .slice(0, 4)
    .map((group) => group.toString(16))
    .join(":")}::/64`;
}

/**
 * The eight 16-bit groups of an IPv6 address, from any spelling Node accepts: compressed or not, any
 * case, leading zeros, and an embedded dotted quad (which supplies the last two groups). Only called
 * after `isIPv6` has validated the address, so the structure is known to be sound.
 */
function expandIPv6(address: string): number[] {
  const [head, tail] = address.includes("::") ? address.split("::") : [address, undefined];
  const parse = (part: string | undefined): number[] => {
    if (!part) return [];
    const out: number[] = [];
    for (const group of part.split(":")) {
      if (group.includes(".")) {
        const [a, b, c, d] = group.split(".").map(Number);
        out.push((a << 8) | b, (c << 8) | d);
      } else {
        out.push(parseInt(group, 16));
      }
    }
    return out;
  };
  const front = parse(head);
  if (tail === undefined) return front;
  const back = parse(tail);
  return [...front, ...new Array<number>(8 - front.length - back.length).fill(0), ...back];
}
