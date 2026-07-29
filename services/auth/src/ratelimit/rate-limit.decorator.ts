import { SetMetadata } from "@nestjs/common";

export const RATE_LIMIT_KEY = "crbk:rate-limit";
export const NO_RATE_LIMIT_KEY = "crbk:no-rate-limit";

export interface RateLimitOptions {
  limit: number;
  windowMs: number;
}

/**
 * Override the default budget for one route or controller.
 *
 * Use it to make a route STRICTER, which is what it is for. The default applies everywhere, so the
 * routes worth naming here are the expensive or security-sensitive ones: anything that hashes a
 * password, sends mail, or provisions infrastructure.
 */
export const RateLimit = (options: RateLimitOptions): MethodDecorator & ClassDecorator =>
  SetMetadata(RATE_LIMIT_KEY, options);

/**
 * Exempt a route from rate limiting.
 *
 * Deliberately rare, and every use needs a reason in a comment. It exists for endpoints an
 * infrastructure component polls on a schedule, where a 429 would take the service out of a load
 * balancer's rotation and turn a rate limit into an outage.
 */
export const NoRateLimit = (): MethodDecorator & ClassDecorator =>
  SetMetadata(NO_RATE_LIMIT_KEY, true);
