import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { FastifyAdapter, type NestFastifyApplication } from "@nestjs/platform-fastify";
import { Logger, ValidationPipe } from "@nestjs/common";
import { loadConfig, loadLocalDotenv } from "@compliance-kit/config";
import { AppModule } from "./app.module";
import { validationExceptionFactory } from "./common/validation-exception.factory";
import { setupOpenApi } from "./docs/openapi";

async function bootstrap(): Promise<void> {
  // Local development convenience; a no-op when NODE_ENV=production, where config is
  // expected to arrive from KMS / Secrets Manager. See @compliance-kit/config.
  loadLocalDotenv();
  const config = loadConfig();

  /**
   * Request limits, all of them denial-of-service controls rather than tuning knobs, which is why the
   * values live in validated config. See @compliance-kit/config for what each one bounds.
   *
   * THE DUPLICATION OF `requestTimeout` BELOW IS REQUIRED. It is not tidy and it is not redundant.
   *
   * Fastify's own `requestTimeout` option does not work on its own for any value under 60s, and fails
   * silently. Node derives `headersTimeout = min(60_000, requestTimeout)` inside `http.createServer`
   * and validates `headersTimeout <= requestTimeout` there and only there. Fastify creates the server
   * first and then assigns `server.requestTimeout = options.requestTimeout` afterwards, without
   * touching `headersTimeout`. So a configured 30s leaves the pair at headersTimeout 60000 and
   * requestTimeout 30000, which violates the invariant the constructor would have rejected, and Node's
   * expiry sweep then never expires anything. The option appears to be set, and nothing is enforced.
   *
   * Fastify does pass `options.http` straight through to `http.createServer`, so putting the timeout
   * there gets the constructor-time derivation right. But the post-construction assignment still runs
   * afterwards with Fastify's own default of 0, which would overwrite it back to "disabled". Hence
   * both: `http.requestTimeout` to derive a consistent `headersTimeout`, and the top-level
   * `requestTimeout` so the assignment that follows writes the same value instead of zero.
   *
   * Verified by socket, not by reading: `pnpm smoke:slowloris` reproduces the dribbled-body attack and
   * asserts the server answers 408 and hangs up. Every combination other than this one leaves the body
   * unbounded, which is how the hole survived being "fixed" once already.
   */
  const httpServerOptions = {
    requestTimeout: config.requestTimeoutMs,
    // Enforcement granularity. Node sweeps the connection list on this interval rather than arming a
    // timer per request, so the effective deadline is the timeout plus up to one interval.
    connectionsCheckingInterval: config.connectionsCheckingIntervalMs,
  };

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      http: httpServerOptions,
      requestTimeout: config.requestTimeoutMs,
      connectionTimeout: config.connectionTimeoutMs,
      keepAliveTimeout: config.keepAliveTimeoutMs,
      bodyLimit: config.bodyLimitBytes,
      /**
       * What `request.ip` means, and therefore what the rate limiter counts.
       *
       * Handed to Fastify rather than parsed in the guard on purpose. X-Forwarded-For is a LIST, and
       * picking the right element is the part everyone gets wrong: the leftmost entry is the one the
       * client supplied and can say anything, so a naive `split(",")[0]` hands every caller a fresh
       * bucket per request. Fastify walks the list from the right against its trusted set.
       *
       * When this is false, `request.ip` is the socket address. See `trustProxy` in
       * @compliance-kit/config for why that has no safe default and which way each mistake fails.
       */
      trustProxy: config.trustProxy,
    }),
  );

  // RFC 8615 reserves /.well-known/ at the root of an origin, so the JWKS route is excluded from
  // the prefix. A well-known URI nested under /api is not a well-known URI.
  app.setGlobalPrefix("api", { exclude: [".well-known/jwks.json"] });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      // Without this, ValidationPipe throws a BadRequestException whose body is its own shape
      // ({message: string[], error, statusCode}), which is one of the three inconsistent error
      // shapes this contract exists to remove. Translating to a DomainError routes it through
      // ProblemDetailsFilter like every other error.
      exceptionFactory: validationExceptionFactory,
    }),
  );
  // The global filter and the response envelope are registered in CoreModule via APP_FILTER
  // and APP_INTERCEPTOR, because both need dependency injection.

  // After the prefix, so the document describes the paths as they are actually served, and before
  // listen(), so the spec is available with the first request rather than on a later one.
  setupOpenApi(app, config);

  // Lets CoreModule close its database pools on SIGTERM instead of dropping them.
  app.enableShutdownHooks();

  await app.listen(config.port, "0.0.0.0");
  new Logger("bootstrap").log(`auth-service listening on :${config.port}`);
}

void bootstrap();
