import { createHash } from "node:crypto";
import { Inject, Injectable, Logger } from "@nestjs/common";
import { TooManyRequestsError } from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import { CONFIG } from "../core/tokens";
import { RateLimitStore } from "../ratelimit/rate-limit.store";

/**
 * Slows password guessing, which the generic per-client rate limit does not.
 *
 * The generic limiter bounds how many requests ONE address may make. That is a throughput control and
 * it does nothing about the two shapes credential attacks actually take: many addresses against one
 * account, and one address against many accounts. So this counts along both axes.
 *
 * TWO COUNTERS, AND THEY BEHAVE DIFFERENTLY ON SUCCESS.
 *
 * The account counter is cleared when a login succeeds. Someone who has just proved they know the
 * password is not guessing it, and without the reset a user who mistyped nine times before getting it
 * right would spend the rest of the window one attempt from being throttled.
 *
 * The address counter is NOT cleared. Clearing it would hand an attacker who controls any single valid
 * account a way to wipe their own address budget on demand: fail against nine accounts, log in to their
 * own, repeat forever. Spraying is exactly what the address counter is for, so its budget has to
 * survive a success.
 *
 * FAILURES ARE COUNTED, NOT ATTEMPTS. A user with the right password is never nearer a limit no matter
 * how often they sign in, so the control is invisible to legitimate traffic and only tightens around
 * guessing. Attempt volume is bounded separately, by the @RateLimit on the route, because verifying a
 * password costs deliberate Argon2 work whether or not the password is right.
 *
 * A THROTTLE RATHER THAN A LOCKOUT. Exceeding the limit returns 429 with a Retry-After and the counter
 * ages out on its own. A hard lock until an administrator intervenes reads as stricter, and is a denial
 * of service anyone can trigger against any account they can name: PCI-DSS 8.3.4 asks for a lockout of
 * at least 30 minutes, and a deployment that needs that reading can set LOGIN_THROTTLE_WINDOW_MS to
 * 1800000. What the kit will not do is provide an unauthenticated way to disable a named user
 * indefinitely.
 */
@Injectable()
export class LoginThrottleService {
  private readonly logger = new Logger(LoginThrottleService.name);

  constructor(
    private readonly store: RateLimitStore,
    @Inject(CONFIG) private readonly config: AppConfig,
  ) {}

  /**
   * Reject before any password work is done, if either counter is already at its limit.
   *
   * Checked before verification for a reason beyond tidiness: verifying is the expensive step, so a
   * throttled attacker who still triggered an Argon2 hash per request would have a CPU exhaustion
   * primitive that the throttle itself paid for.
   */
  async assertWithinLimits(tenantId: string, email: string, ip: string): Promise<void> {
    const [account, address] = await Promise.all([
      this.store.peek(
        this.accountKey(tenantId, email),
        this.config.loginThrottleLimit,
        this.config.loginThrottleWindowMs,
      ),
      this.store.peek(
        this.addressKey(ip),
        this.config.loginThrottleLimit,
        this.config.loginThrottleWindowMs,
      ),
    ]);

    // The longer of the two waits, so a caller told to come back in N seconds is not still throttled
    // by the other counter when they do.
    if (!account.allowed || !address.allowed) {
      const retryAfterMs = Math.max(
        account.allowed ? 0 : account.retryAfterMs,
        address.allowed ? 0 : address.retryAfterMs,
      );
      // Logged with the reason, which the response deliberately omits: telling a caller whether it was
      // the account or the address that tripped tells them whether the account exists.
      this.logger.warn(
        `Login throttled for tenant ${tenantId} from ${ip} ` +
          `(account=${account.count}/${account.limit}, address=${address.count}/${address.limit})`,
      );
      throw new TooManyRequestsError(retryAfterMs);
    }
  }

  /** Count one failed attempt against both the account and the source address. */
  async recordFailure(tenantId: string, email: string, ip: string): Promise<void> {
    await Promise.all([
      this.store.consume(
        this.accountKey(tenantId, email),
        this.config.loginThrottleLimit,
        this.config.loginThrottleWindowMs,
      ),
      this.store.consume(
        this.addressKey(ip),
        this.config.loginThrottleLimit,
        this.config.loginThrottleWindowMs,
      ),
    ]);
  }

  /** Clear the account counter after a successful login. See the class comment for why not the address. */
  async recordSuccess(tenantId: string, email: string): Promise<void> {
    await this.store.reset(this.accountKey(tenantId, email));
  }

  /**
   * Email addresses are hashed into the key rather than written in plain.
   *
   * Key hygiene, not encryption, and worth stating precisely so nobody mistakes it for the latter:
   * anyone holding the key list and a guess at an address can confirm it by hashing, because an email
   * address has far too little entropy for a bare digest to hide. What it does buy is that the address
   * is not sitting in a Redis keyspace, and not in whatever `KEYS *`, `MONITOR`, a slow-log entry, or a
   * support engineer's terminal history would otherwise show. Redis is a cache, usually with weaker
   * access control and no encryption at rest, and a directory of every user who has ever mistyped a
   * password is not something to leave lying in one.
   *
   * Scoped by tenant, because the same address in two tenants is two accounts and must have two
   * budgets. Sharing them would let a failure in one tenant throttle a user in another.
   */
  private accountKey(tenantId: string, email: string): string {
    const digest = createHash("sha256")
      .update(`${tenantId}:${email.trim().toLowerCase()}`)
      .digest("base64url")
      .slice(0, 32);
    return `login:acct:${digest}`;
  }

  private addressKey(ip: string): string {
    return `login:addr:${ip}`;
  }
}
