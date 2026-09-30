import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { registerDefaultResponseHeaders } from "./default-response-headers";

/** A real Fastify instance and `inject`, so the hook runs exactly where it runs in production. */
function server() {
  const app = Fastify();
  registerDefaultResponseHeaders(app);
  app.get("/data", () => ({ ok: true }));
  app.get("/cacheable", (_request, reply) => {
    reply.header("cache-control", "public, max-age=300, must-revalidate");
    return { keys: [] };
  });
  app.get("/fails", (_request, reply) => {
    reply.status(401);
    return { success: false };
  });
  return app;
}

describe("registerDefaultResponseHeaders", () => {
  it("marks a response no-store and nosniff when its route set neither", async () => {
    const res = await server().inject({ method: "GET", url: "/data" });
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  // The JWKS is cacheable on purpose. Overriding a route's own choice would break it.
  it("leaves a route's own Cache-Control alone", async () => {
    const res = await server().inject({ method: "GET", url: "/cacheable" });
    expect(res.headers["cache-control"]).toBe("public, max-age=300, must-revalidate");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("applies to error responses too", async () => {
    const res = await server().inject({ method: "GET", url: "/fails" });
    expect(res.statusCode).toBe(401);
    expect(res.headers["cache-control"]).toBe("no-store");
  });

  it("applies to an unmatched route", async () => {
    const res = await server().inject({ method: "GET", url: "/nowhere" });
    expect(res.statusCode).toBe(404);
    expect(res.headers["cache-control"]).toBe("no-store");
  });
});
