import {
  Global,
  Inject,
  Logger,
  Module,
  type OnApplicationShutdown,
  type OnModuleInit,
} from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { Redis } from "ioredis";
import type { AppConfig } from "@compliance-kit/config";
import { CONFIG } from "../core/tokens";
import { RateLimitGuard } from "./rate-limit.guard";
import { RateLimitStore } from "./rate-limit.store";
import { REDIS } from "./tokens";

/**
 * Owns the Redis connection and registers the global rate limit.
 *
 * `@Global()` for the same reason TenancyModule and AuthModule are: the limiter is infrastructure that
 * applies to every route, and a feature module should not have to import anything to be covered by it.
 * Coverage that depends on remembering an import is coverage with holes.
 */
@Global()
@Module({
  providers: [
    {
      provide: REDIS,
      inject: [CONFIG],
      useFactory: (config: AppConfig): Redis => {
        const logger = new Logger("Redis");
        const client = new Redis(config.redisUrl, {
          /**
           * The three options below exist so a Redis outage degrades the limiter rather than hanging
           * the API, and they only make sense together.
           *
           * `enableOfflineQueue: false` is the important one. By default ioredis QUEUES commands while
           * disconnected and resolves them after reconnecting, so a limiter check during an outage
           * does not fail, it waits. Every request then parks in the guard, holding a connection,
           * until Redis returns or the request times out. That converts a Redis outage into an
           * application-wide stall, which is worse than the unmetered traffic that failing open
           * allows. With the queue off, a check during an outage rejects immediately and the store's
           * fail-open policy applies straight away.
           */
          enableOfflineQueue: false,
          // One retry, so a single dropped packet does not degrade the limiter, but a real outage is
          // reported in milliseconds rather than after a retry ladder.
          maxRetriesPerRequest: 1,
          // Do not connect during construction, so an unreachable Redis cannot stop the service from
          // booting. It boots degraded and says so, which beats refusing to start: the token keys and
          // the database are what the API actually needs to serve a request.
          //
          // The connection is then opened explicitly in onModuleInit rather than left to the first
          // command. See the comment there: leaving it lazy means the first request after every restart
          // is not rate limited at all.
          lazyConnect: true,
          connectTimeout: 3_000,
          // Namespaced so the kit's keys are recognisable in a shared Redis, and so a FLUSH scoped by
          // prefix cannot take out another application's data.
          keyPrefix: "crbk:",
        });

        // ioredis emits `error` on every failed reconnection attempt. Unhandled, those become
        // uncaught exceptions that kill the process, which is exactly the outage the settings above
        // are meant to avoid.
        client.on("error", (err: Error) => {
          logger.error(`Redis connection error: ${err.message}`);
        });
        client.on("ready", () => {
          logger.log(`Connected to Redis, rate limiting is active`);
        });

        if (!config.rateLimitFailOpen) {
          logger.warn(
            "RATE_LIMIT_FAIL_OPEN is false: Redis is now a hard dependency for serving any request",
          );
        }
        return client;
      },
    },
    RateLimitStore,
    { provide: APP_GUARD, useClass: RateLimitGuard },
  ],
  exports: [REDIS, RateLimitStore],
})
export class RateLimitModule implements OnModuleInit, OnApplicationShutdown {
  private readonly logger = new Logger(RateLimitModule.name);

  constructor(@Inject(REDIS) private readonly redis: Redis) {}

  /**
   * Open the connection at boot rather than on the first command.
   *
   * `lazyConnect` alone is not enough, and the gap it leaves was found by watching response headers
   * rather than by reasoning: the FIRST request after every restart came back
   * `x-ratelimit-degraded: true`. With `enableOfflineQueue: false` a command issued while the socket is
   * still being established fails instead of waiting, so that request was not rate limited at all.
   * Harmless once, but it is a hole that reopens on every deploy and every restart.
   *
   * Connecting here keeps both properties: the process still starts when Redis is down, because the
   * failure is caught and logged rather than thrown, and in the normal case the limiter is ready before
   * the first request arrives.
   */
  async onModuleInit(): Promise<void> {
    try {
      await this.redis.connect();
    } catch (err) {
      // Already reported by the client's own error handler; this says what it means for the service.
      this.logger.error(
        `Redis is unreachable at startup, rate limiting starts degraded: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  async onApplicationShutdown(): Promise<void> {
    // quit() waits for in-flight commands and closes cleanly; disconnect() would drop them. On a
    // rolling deploy the difference is whether the last few requests get a limiter answer.
    await this.redis.quit().catch(() => this.redis.disconnect());
  }
}
