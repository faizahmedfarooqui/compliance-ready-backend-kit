import { CanActivate, ExecutionContext, Inject, Injectable, Logger } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { FastifyReply, FastifyRequest } from "fastify";
import { TooManyRequestsError } from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import { CONFIG } from "../core/tokens";
import { RateLimitStore, type RateLimitResult } from "./rate-limit.store";
import { NO_RATE_LIMIT_KEY, RATE_LIMIT_KEY, type RateLimitOptions } from "./rate-limit.decorator";

/**
 * Global rate limit, applied to every request that has not opted out.
 *
 * TWO BUDGETS, and a route carrying `@RateLimit` is checked against both.
 *
 * The first is a single budget per client across the whole API. That is the denial-of-service control:
 * without it a caller simply spreads load over many routes, each of which is individually within its
 * own limit, and the sum is unbounded.
 *
 * The second applies only where a route declares its own stricter limit. It is checked IN ADDITION to
 * the global budget rather than instead of it, because a route saying "five per hour" is asking for
 * less than the default, never for a fresh allowance on top of it. Replacing the global check would
 * turn every strict annotation into an escape hatch that grants extra total throughput, which is the
 * opposite of what the annotation says.
 *
 * A route with no annotation costs one Redis round trip. Only annotated routes pay for two.
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly store: RateLimitStore,
    @Inject(CONFIG) private readonly config: AppConfig,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Only HTTP has a client address to key on. Anything else (a future queue consumer) is not
    // reachable by an anonymous caller and has nothing meaningful to limit.
    if (context.getType() !== "http") return true;

    const exempt = this.reflector.getAllAndOverride<boolean>(NO_RATE_LIMIT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (exempt) return true;

    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const reply = context.switchToHttp().getResponse<FastifyReply>();
    const client = this.clientId(request);

    const global = await this.store.consume(
      `rl:client:${client}`,
      this.config.rateLimitDefaultLimit,
      this.config.rateLimitDefaultWindowMs,
    );
    this.setHeaders(reply, global);
    if (!global.allowed) throw new TooManyRequestsError(global.retryAfterMs);

    const route = this.reflector.getAllAndOverride<RateLimitOptions | undefined>(RATE_LIMIT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (route) {
      // Keyed by the route, so a strict budget on one endpoint is not consumed by traffic to another.
      // `routeOptions.url` is the route PATTERN ("/api/tenants/:id"), not the resolved URL, so an
      // attacker cannot mint unlimited buckets by varying a path parameter.
      //
      // The fallback has to drop the query string. `request.url` includes it, so `?x=1`, `?x=2` and so
      // on would each be a distinct key: unbounded Redis keys, and a per-route budget that resets on
      // every cache-busting parameter, which turns the strictest limits in the kit into no limit.
      const pattern = request.routeOptions?.url ?? request.url.split("?")[0];
      const scoped = await this.store.consume(
        `rl:route:${request.method}:${pattern}:${client}`,
        route.limit,
        route.windowMs,
      );
      // Headers describe the tighter of the two, since that is the limit the caller will hit first.
      this.setHeaders(reply, scoped);
      if (!scoped.allowed) throw new TooManyRequestsError(scoped.retryAfterMs);
    }

    return true;
  }

  /**
   * Who to charge for this request.
   *
   * `request.ip` is Fastify's, which means it honours the adapter's `trustProxy` setting and does the
   * X-Forwarded-For parsing properly rather than naively taking the first entry. Reading the header
   * here instead would hand every caller a free bucket per request, because the header is caller
   * supplied unless something trusted overwrites it. See `trustProxy` in @compliance-kit/config for
   * why that setting has no safe default.
   *
   * An unresolvable address falls back to one shared bucket rather than to an exemption. That means
   * such requests limit each other, which is the conservative direction: the alternative is a hole
   * that opens whenever the address is unavailable.
   */
  private clientId(request: FastifyRequest): string {
    const ip = request.ip;
    if (typeof ip === "string" && ip.length > 0) return ip;
    this.logger.warn("Request with no resolvable client address; using the shared fallback bucket");
    return "unknown";
  }

  /**
   * `X-RateLimit-*`, deliberately, rather than the `RateLimit` and `RateLimit-Policy` fields from
   * draft-ietf-httpapi-ratelimit-headers. Those are the better design and will probably win, but they
   * are still an Internet-Draft, and this kit does not claim conformance to specifications that have
   * not been published. The X- names are what clients and gateways actually parse today.
   */
  private setHeaders(reply: FastifyReply, result: RateLimitResult): void {
    /**
     * This runs TWICE on a route with its own budget, so the two branches have to undo each other or
     * the response ends up carrying both a budget and the degraded flag. That combination contradicts
     * docs/problems.md and, worse, tells a client a limit was checked when it was not.
     */
    if (result.degraded) {
      // Nothing truthful to report: sending limit and remaining would state a budget that was never
      // checked. Remove any an earlier check already set.
      reply.removeHeader("x-ratelimit-limit");
      reply.removeHeader("x-ratelimit-remaining");
      reply.header("x-ratelimit-degraded", "true");
      return;
    }

    /**
     * DEGRADATION IS STICKY, and this is a deliberate departure from the obvious fix of clearing the
     * flag whenever a check succeeds.
     *
     * If the global check degraded and the route check then succeeded, the request really was partly
     * unmetered: one of the two budgets was never consulted. Clearing the flag because the second check
     * worked would report full enforcement of something half enforced, which is the direction a
     * security signal must never round in. So once anything degrades, the response says so and carries
     * no figures.
     */
    if (reply.getHeader("x-ratelimit-degraded") !== undefined) return;

    reply.header("x-ratelimit-limit", String(result.limit));
    reply.header("x-ratelimit-remaining", String(Math.max(0, result.limit - result.count)));
  }
}
