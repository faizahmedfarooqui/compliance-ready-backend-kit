import type { FastifyInstance } from "fastify";

/**
 * Headers every response carries unless its route set its own.
 *
 * `Cache-Control: no-store`, because the defaults this API would otherwise inherit are wrong for it. The
 * login response carries a bearer token and the data routes carry user records, and neither should be
 * kept by any cache, the browser's included. It is the same rule RFC 6749 section 5.1 sets for OAuth
 * token responses: "Cache-Control" with a value of "no-store" on any response containing tokens,
 * credentials, or other sensitive information. Before this, only a 429 said so (RFC 6585 requires it
 * there). Shared caches mostly refuse a POST response or one to an authenticated request anyway, but
 * "mostly" and "anyway" are not a control.
 *
 * `X-Content-Type-Options: nosniff`, so a browser renders a response as the type it declares rather
 * than one it guesses. Every response here is JSON, problem+json, a JWK Set or the docs UI, all with an
 * accurate Content-Type, so the header costs nothing.
 *
 * "Unless its route set its own" is load-bearing. The JWKS is cacheable on purpose (`public, max-age`),
 * and @fastify/static sets cache headers on the docs UI's assets; overriding either would be a
 * regression dressed as hardening. Nest's `useSecurityHeaders()` was not used, because its default
 * Content-Security-Policy would break the Swagger UI at /docs, and a policy tuned for that belongs with
 * a decision about whether /docs should be served at all.
 */
export function registerDefaultResponseHeaders(fastify: FastifyInstance): void {
  fastify.addHook("onSend", (_request, reply, payload, done) => {
    if (!reply.hasHeader("cache-control")) reply.header("cache-control", "no-store");
    if (!reply.hasHeader("x-content-type-options"))
      reply.header("x-content-type-options", "nosniff");
    done(null, payload);
  });
}
