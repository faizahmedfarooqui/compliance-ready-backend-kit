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

  const lower = address.toLowerCase().split("%")[0];
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (mapped && isIPv4(mapped[1])) return mapped[1];

  return `${firstFourHextets(lower)}::/64`;
}

/** The first 64 bits of an IPv6 address, in canonical lowercase hextets without leading zeros. */
function firstFourHextets(address: string): string {
  const [head, tail] = address.includes("::") ? address.split("::") : [address, undefined];
  const hextets = (part: string | undefined): string[] => {
    if (!part) return [];
    const groups = part.split(":");
    // A trailing dotted quad occupies the last two hextets. It can never reach the first four, so its
    // value does not matter, only that it is counted as two groups.
    if (groups[groups.length - 1].includes(".")) groups.splice(-1, 1, "0", "0");
    return groups;
  };
  const front = hextets(head);
  const back = hextets(tail);
  const full =
    tail === undefined
      ? front
      : [...front, ...new Array<string>(8 - front.length - back.length).fill("0"), ...back];
  return full
    .slice(0, 4)
    .map((group) => parseInt(group, 16).toString(16))
    .join(":");
}
