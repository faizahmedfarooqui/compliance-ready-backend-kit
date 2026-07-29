import { randomBytes } from "node:crypto";
import { Inject, Injectable, Logger } from "@nestjs/common";
import type { Redis } from "ioredis";
import type { AppConfig } from "@compliance-kit/config";
import { CONFIG } from "../core/tokens";
import { REDIS } from "./tokens";

/**
 * The counting half of rate limiting. Knows nothing about HTTP: it answers "may this identity do one
 * more thing in this window", and the guard decides what that means for a request.
 *
 * SLIDING WINDOW, not a fixed one. A fixed window counter is a line of code shorter and permits twice
 * the limit across a boundary: with 10 per minute, ten attempts at 11:59:59 and ten more at 12:00:00
 * are twenty in one second and every one of them is inside the limit. For a request budget that is
 * merely untidy. For login throttling it is the whole control, because the burst is exactly what an
 * attacker wants and the boundary is a free parameter they can find by trying.
 *
 * The window is kept as a sorted set of timestamps, one member per counted event. That makes the
 * count exact rather than approximate, and the memory is bounded by the LIMIT rather than by traffic,
 * because once the limit is reached the script stops adding members. Ten failures per account costs
 * ten small members; a flood against the same key costs the same ten.
 */

/** Outcome of one consume attempt. */
export interface RateLimitResult {
  allowed: boolean;
  /** Events counted in the window, after this one if it was allowed. */
  count: number;
  limit: number;
  /** Milliseconds until the window has room again. Zero when allowed. */
  retryAfterMs: number;
  /**
   * True when the limiter could not reach Redis and the configured fail-open policy let the request
   * through. The guard reports this so a degraded control is visible rather than silent.
   */
  degraded: boolean;
}

/**
 * Sliding window, evaluated atomically inside Redis.
 *
 * Atomicity is the point of using a script at all. The read-modify-write here is CHECK the count,
 * then ADD a member, and any gap between those two lets concurrent requests all observe count = 9
 * and all decide they are the tenth. Rate limiting is most interesting under exactly the concurrency
 * that makes that gap likely, so a limiter with a race is a limiter that fails when tested.
 *
 * Time comes from `TIME` on the server rather than from the caller. Every application instance
 * therefore scores members on one clock, so a machine whose NTP has drifted cannot widen or narrow
 * its own view of the window. Redis has replicated script EFFECTS rather than the script itself
 * since 5.0, so a non-deterministic command is no longer a replication hazard.
 *
 * KEYS[1] the bucket. ARGV[1] window in ms, ARGV[2] limit, ARGV[3] a unique member id.
 * Returns {allowed, count, retryAfterMs}.
 */
const SLIDING_WINDOW = `
local window = tonumber(ARGV[1])
local limit   = tonumber(ARGV[2])
local member  = ARGV[3]

local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)

-- Drop everything that has aged out. This is what makes the window slide rather than hop.
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)

local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
  -- A slot frees up when the OLDEST surviving event leaves the window, so that is what the caller
  -- must wait for. Reporting the whole window instead would overstate the wait for anyone who has
  -- been throttled for a while, and clients honour Retry-After literally.
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  local retry = window - (now - tonumber(oldest[2]))
  if retry < 0 then retry = 0 end
  -- Deliberately no ZADD here. A rejected attempt is not recorded, so hammering a throttled key
  -- cannot keep pushing the oldest entry forward and extend the lockout indefinitely. Otherwise an
  -- attacker could hold a legitimate user out for as long as they cared to keep trying.
  return {0, count, retry}
end

redis.call('ZADD', KEYS[1], now, member)
-- Refreshed on every accepted event so an abandoned bucket disappears on its own. Without this the
-- key would live forever for any identity that never comes back.
redis.call('PEXPIRE', KEYS[1], window)
return {1, count + 1, 0}
`;

/**
 * Read the window without recording anything.
 *
 * Needed because login throttling counts FAILURES, not attempts. The check has to happen before the
 * password is verified, and if that check consumed budget then every successful login would spend
 * from the same allowance as a failed one, so a busy legitimate user would throttle themselves.
 *
 * Returns {count, retryAfterMs}.
 */
const PEEK_WINDOW = `
local window = tonumber(ARGV[1])

local time = redis.call('TIME')
local now = (tonumber(time[1]) * 1000) + math.floor(tonumber(time[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])
if count == 0 then
  return {0, 0}
end

local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local retry = window - (now - tonumber(oldest[2]))
if retry < 0 then retry = 0 end
return {count, retry}
`;

interface WindowCommand {
  slidingWindow(
    key: string,
    window: string,
    limit: string,
    member: string,
  ): Promise<[number, number, number]>;
  peekWindow(key: string, window: string): Promise<[number, number]>;
}

/**
 * Builds unique event ids for the sorted-set members.
 *
 * Random rather than derived from anything about the host, because everything identifying about a host
 * is either shared or reused. `process.pid` was the original choice and it is actively wrong in a
 * container: PID 1 is what a containerised process gets, so every replica and every restart produced
 * the same value. Hostname has the same problem behind a scheduler that reuses names, and a start
 * timestamp collides whenever replicas boot together, which is exactly what a rolling deploy does.
 *
 * 64 bits of randomness to separate processes, plus a monotonic counter so collisions WITHIN a process
 * are impossible rather than merely unlikely. See `consume` for what a collision would cost.
 */
export function newMemberIdFactory(): () => string {
  const instanceId = randomBytes(8).toString("base64url");
  let counter = 0;
  return () => {
    counter += 1;
    return `${instanceId}:${counter}`;
  };
}

/**
 * One factory for the whole process, shared by every store in it.
 *
 * Module scope on purpose. Held per store instead, the guarantee would quietly depend on there being
 * exactly one RateLimitStore per process: two would each start a counter at zero. Nest constructs one
 * today, so that could not bite yet, and "could not bite yet" is how the pid version survived too.
 *
 * Exported as a factory so a test can build a SECOND one and assert the two never collide. That is what
 * a replica or a restart is, and it cannot be reached with one shared module-level constant.
 */
const nextMemberId = newMemberIdFactory();

@Injectable()
export class RateLimitStore {
  private readonly logger = new Logger(RateLimitStore.name);

  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    @Inject(CONFIG) private readonly config: AppConfig,
  ) {
    // defineCommand registers the script once and calls it by SHA thereafter, falling back to a
    // full EVAL only when the server has not seen it. That matters because the script text is sent
    // on every call otherwise, which for a limiter on every request is a lot of identical bytes.
    this.redis.defineCommand("slidingWindow", { numberOfKeys: 1, lua: SLIDING_WINDOW });
    this.redis.defineCommand("peekWindow", { numberOfKeys: 1, lua: PEEK_WINDOW });
  }

  /**
   * How full the window is, without counting this look as an event.
   *
   * Fails OPEN regardless of the configured policy, and that is not an inconsistency. The only caller
   * is login throttling, where the failure count is consulted before the password is checked; a Redis
   * outage that made this reject would lock every user out of the service entirely. The password check
   * itself is unaffected, so an outage costs the throttle, not the authentication.
   */
  async peek(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    try {
      const client = this.redis as unknown as WindowCommand;
      const [count, retryAfterMs] = await client.peekWindow(key, String(windowMs));
      return { allowed: count < limit, count, limit, retryAfterMs, degraded: false };
    } catch (err) {
      this.logger.error(
        `Could not read the rate-limit window for "${key}", allowing: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
      return { allowed: true, count: 0, limit, retryAfterMs: 0, degraded: true };
    }
  }

  /**
   * Count one event against `key` and say whether it is allowed.
   *
   * Never throws. A limiter that can fail a request by falling over is a new outage cause bolted to
   * every route, so a Redis failure resolves to the configured fail-open policy and is logged.
   */
  async consume(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    /**
     * The member has to be unique across EVERY process that shares this Redis, not just within this
     * one, and getting that wrong fails silently in the worst direction.
     *
     * A sorted set is keyed by its member: `ZADD` on a member that already exists UPDATES its score and
     * returns 0 rather than adding a second entry, so `ZCARD` does not grow. A repeated member is
     * therefore an event that is not counted, and the limiter permits more than it says while looking
     * healthy from the outside.
     *
     * This was `${process.pid}:${counter}`, which is unique within one process and nowhere near unique
     * outside it. A containerised process gets PID 1, and the counter restarts at 1, so every replica
     * and every restart replayed the identical sequence `1:1`, `1:2`, `1:3`. Two replicas behind a load
     * balancer would then overwrite each other's entries continuously: with the same client's requests
     * spread across them, most events after the first from each index would not be counted at all. Not
     * an edge case, and not limited to restarts, which is how it survived a review of the comment that
     * claimed the member was unique.
     *
     * A random per-process id plus a monotonic counter fixes both halves at once: the counter makes
     * collisions within a process impossible rather than improbable, so the randomness only has to
     * separate processes, and 64 bits does that with room to spare.
     */
    const member = nextMemberId();

    try {
      const client = this.redis as unknown as WindowCommand;
      const [allowed, count, retryAfterMs] = await client.slidingWindow(
        key,
        String(windowMs),
        String(limit),
        member,
      );
      return { allowed: allowed === 1, count, limit, retryAfterMs, degraded: false };
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Rate limiter could not reach Redis, ${this.config.rateLimitFailOpen ? "ALLOWING" : "REJECTING"} ` +
          `request for "${key}": ${reason}`,
      );
      return {
        allowed: this.config.rateLimitFailOpen,
        count: 0,
        limit,
        // Short, because the outage is the reason for the rejection and it may already be over. A
        // long Retry-After derived from the window would punish callers for our own failure.
        retryAfterMs: this.config.rateLimitFailOpen ? 0 : 1_000,
        degraded: true,
      };
    }
  }

  /**
   * Forget a key entirely.
   *
   * Used when a login succeeds: the failure count exists to slow guessing, and someone who has just
   * proved they know the password is not guessing. Without this, a user who mistyped nine times and
   * then got it right would stay one attempt from a lockout for the rest of the window.
   */
  async reset(key: string): Promise<void> {
    try {
      await this.redis.del(key);
    } catch (err) {
      // Non-fatal by construction: the bucket expires on its own, so the worst case is that a user
      // keeps a stale failure count until the window rolls over.
      this.logger.warn(
        `Could not clear rate-limit key "${key}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}
