import { describe, expect, it } from "vitest";
import { BadRequestException, HttpException, HttpStatus, NotFoundException } from "@nestjs/common";
import type { ArgumentsHost } from "@nestjs/common";
import type { AppConfig } from "@compliance-kit/config";
import {
  ControlPlaneUnauthorizedError,
  CrossTenantTokenError,
  EmailAlreadyRegisteredError,
  InvalidAccessTokenError,
  InvalidCredentialsError,
  TenantAlreadyExistsError,
  TenantNotFoundError,
  TooManyRequestsError,
  ValidationFailedError,
  type ProblemDetails,
} from "@compliance-kit/common";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CODE_BY_STATUS, ProblemDetailsFilter } from "./problem-details.filter";

/**
 * The filter every error passes through. Its job is that a client sees one shape whatever failed,
 * and that a 500 discloses nothing. Both are asserted here rather than left to the smoke test,
 * because the interesting inputs (an arbitrary thrown value) are awkward to provoke over HTTP.
 */

const BASE = "https://example.test/problems.md";
const config = { problemTypeBaseUri: BASE } as AppConfig;

function capture(exception: unknown, url = "/api/users") {
  const sent: { status?: number; headers: Record<string, string>; body?: ProblemDetails } = {
    headers: {},
  };
  const reply = {
    status(code: number) {
      sent.status = code;
      return this;
    },
    header(name: string, value: string) {
      sent.headers[name] = value;
      return this;
    },
    send(body: ProblemDetails) {
      sent.body = body;
      return this;
    },
  };
  const host = {
    switchToHttp: () => ({
      getResponse: () => reply,
      getRequest: () => ({ url, method: "GET" }),
    }),
  } as unknown as ArgumentsHost;

  new ProblemDetailsFilter(config).catch(exception, host);
  return sent;
}

describe("ProblemDetailsFilter", () => {
  it("serves application/problem+json, as RFC 9457 s3 requires", () => {
    const { headers } = capture(new TenantNotFoundError("acme"));
    expect(headers["content-type"]).toBe("application/problem+json; charset=utf-8");
  });

  it("includes all five RFC 9457 members plus the code and traceId extensions", () => {
    const { body } = capture(new TenantNotFoundError("acme"));
    expect(body).toMatchObject({
      success: false,
      type: `${BASE}#tenant-not-found`,
      title: "Unknown or inactive tenant",
      status: 404,
      detail: "Unknown or inactive tenant: acme",
      code: "TENANT_NOT_FOUND",
    });
    expect(body?.instance).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
  });

  // s3.1.2: the advisory `status` member must equal the real status line.
  it("keeps the status member and the response status in agreement", () => {
    const { status, body } = capture(new TenantAlreadyExistsError("acme"));
    expect(status).toBe(HttpStatus.CONFLICT);
    expect(body?.status).toBe(HttpStatus.CONFLICT);
  });

  it("uses the same uuid for instance and traceId", () => {
    const { body } = capture(new InvalidCredentialsError());
    expect(body?.instance).toBe(`urn:uuid:${body?.traceId}`);
  });

  it("gives each occurrence a distinct traceId", () => {
    const a = capture(new InvalidCredentialsError()).body?.traceId;
    const b = capture(new InvalidCredentialsError()).body?.traceId;
    expect(a).not.toBe(b);
  });

  it.each([
    [new InvalidCredentialsError(), 401, "INVALID_CREDENTIALS"],
    [new InvalidAccessTokenError(), 401, "INVALID_ACCESS_TOKEN"],
    [new CrossTenantTokenError(), 401, "CROSS_TENANT_TOKEN"],
    [new TenantNotFoundError("x"), 404, "TENANT_NOT_FOUND"],
    [new EmailAlreadyRegisteredError(), 409, "EMAIL_ALREADY_REGISTERED"],
  ])("maps %s to the right status and code", (err, status, code) => {
    const sent = capture(err);
    expect(sent.status).toBe(status);
    expect(sent.body?.code).toBe(code);
  });

  it("derives the type URI from the code, so it resolves to a docs anchor", () => {
    const { body } = capture(new CrossTenantTokenError());
    expect(body?.type).toBe(`${BASE}#cross-tenant-token`);
  });

  /**
   * A 429 carries two headers beyond the body, and both are specified rather than stylistic, which is
   * why they are asserted here rather than trusted to the guard that raises the error.
   */
  describe("rate limit responses", () => {
    it("map to 429 with the documented code", () => {
      const { status, body } = capture(new TooManyRequestsError(5_000));
      expect(status).toBe(429);
      expect(body?.code).toBe("TOO_MANY_REQUESTS");
    });

    // RFC 9110 s10.2.3: delay-seconds is a non-negative integer, so no fraction and no minus sign.
    it("send Retry-After as a non-negative integer number of seconds", () => {
      const { headers } = capture(new TooManyRequestsError(4_200));
      expect(headers["retry-after"]).toBe("5");
      expect(headers["retry-after"]).toMatch(/^\d+$/);
    });

    // Rounded up and floored at 1: "0" would tell a client to retry immediately, which is the opposite
    // of what a rate limit means.
    it("never send Retry-After: 0", () => {
      for (const ms of [0, 1, 200, -100]) {
        expect(capture(new TooManyRequestsError(ms)).headers["retry-after"]).toBe("1");
      }
    });

    /**
     * RFC 6585 s4: a 429 "MUST NOT be stored by a cache". Without this a shared cache could hand the
     * rejection to callers who are within their limit, or keep serving it after the window passed.
     */
    it("forbid caching", () => {
      expect(capture(new TooManyRequestsError(1_000)).headers["cache-control"]).toBe("no-store");
    });

    // Only on a 429. A Retry-After on an unrelated error would tell clients to back off from something
    // that retrying will never fix.
    it("do not leak those headers onto other errors", () => {
      const { headers } = capture(new TenantNotFoundError("acme"));
      expect(headers["retry-after"]).toBeUndefined();
      expect(headers["cache-control"]).toBeUndefined();
    });
  });

  describe("control-plane rejections", () => {
    it("map to 401 with a code a client can branch on", () => {
      const { status, body } = capture(new ControlPlaneUnauthorizedError());
      expect(status).toBe(401);
      expect(body?.code).toBe("CONTROL_PLANE_UNAUTHORIZED");
    });

    // The type URI has to resolve to a real heading in problems.md, or RFC 9457's promise that
    // dereferencing it yields documentation is false.
    it("point their type URI at the documented anchor", () => {
      const { body } = capture(new ControlPlaneUnauthorizedError());
      expect(body?.type).toMatch(/#control-plane-unauthorized$/);
    });
  });

  describe("validation failures", () => {
    const failure = new ValidationFailedError([
      { detail: "slug must be lowercase", pointer: "#/slug" },
    ]);

    // Well-formed JSON with unacceptable values. 400 is reserved for a body that would not parse.
    it("are 422, not 400", () => {
      expect(capture(failure).status).toBe(HttpStatus.UNPROCESSABLE_ENTITY);
    });

    it("carry the errors extension from RFC 9457 s3.2", () => {
      expect(capture(failure).body?.errors).toEqual([
        { detail: "slug must be lowercase", pointer: "#/slug" },
      ]);
    });

    it("omit the errors extension on problems that are not validation failures", () => {
      expect(capture(new InvalidCredentialsError()).body?.errors).toBeUndefined();
    });
  });

  describe("framework exceptions", () => {
    it("normalise an unmatched route into the same shape", () => {
      const { status, body } = capture(new NotFoundException("Cannot GET /api/nope"));
      expect(status).toBe(404);
      expect(body).toMatchObject({
        success: false,
        code: "ROUTE_NOT_FOUND",
        title: "Resource not found",
        detail: "Cannot GET /api/nope",
      });
    });

    it("give an unparseable body a distinct code from a validation failure", () => {
      const { status, body } = capture(new BadRequestException("Body is not valid JSON"));
      expect(status).toBe(400);
      expect(body?.code).toBe("MALFORMED_REQUEST");
    });

    it("flatten an array message into one detail string", () => {
      const { body } = capture(new BadRequestException({ message: ["first", "second"] }));
      expect(body?.detail).toBe("first; second");
    });

    it("fall back to a generic detail when the body has no usable message", () => {
      const { body } = capture(new BadRequestException({ weird: true }), "/api/thing");
      expect(body?.detail).toContain("/api/thing");
    });
  });

  describe("unexpected errors", () => {
    // The disclosure control: the cause goes to the log, never to the client.
    it("become a 500 that reveals nothing about the cause", () => {
      const secret = new Error("connect ECONNREFUSED 10.0.0.5:5432 password=hunter2");
      const { status, body } = capture(secret);

      expect(status).toBe(500);
      expect(body?.code).toBe("INTERNAL_ERROR");

      const serialised = JSON.stringify(body);
      for (const leak of ["ECONNREFUSED", "10.0.0.5", "5432", "hunter2", "password"]) {
        expect(serialised).not.toContain(leak);
      }
    });

    it("still hand back a traceId so the log line can be found", () => {
      const { body } = capture(new Error("boom"));
      expect(body?.traceId).toMatch(/^[0-9a-f-]{36}$/);
      expect(body?.detail).toContain(body?.traceId ?? "");
    });

    it("handle a thrown non-Error without crashing the filter", () => {
      expect(capture("just a string").status).toBe(500);
      expect(capture(undefined).status).toBe(500);
      expect(capture({ nested: { thing: 1 } }).status).toBe(500);
    });

    it("keep the cause out of the response body entirely", () => {
      // Asserting the *absence* of the cause is the property worth testing. That the message
      // reaches the log is verified end to end in scripts/smoke-test.sh, where the real logger
      // writes to a real stream; asserting it here would mean reaching into a private field.
      const { body } = capture(new Error("sensitive detail here"));
      expect(JSON.stringify(body)).not.toContain("sensitive detail here");
    });
  });
});

/**
 * The one promise RFC 9457 makes about `type` is that dereferencing it yields documentation
 * (s3.1.1). Ours is derived from the code, so keeping that promise means every code the filter
 * can emit must have a heading in problems.md.
 *
 * This READS problems.md. An earlier version of this suite only asserted that a derived `type`
 * matched a regex, which proves the string was built correctly and nothing about whether the
 * target exists. It passed while four emittable codes (method-not-allowed, not-acceptable,
 * payload-too-large, unsupported-media-type) pointed at headings that were never written, and
 * while FORBIDDEN pointed at `#http-403` before it was mapped. A test that asserts a derived
 * string is not a test that the target exists.
 */
describe("every emittable type URI resolves to a documented anchor", () => {
  // Resolved from the repo root, which is where vitest resolves its config from. The
  // "has parsed the catalogue at all" guard below fails loudly if this path ever misses.
  const catalogue = readFileSync(resolve(process.cwd(), "problems.md"), "utf8");
  // Catalogue entries are `### \`kebab-code\``.
  const documented = new Set([...catalogue.matchAll(/^### `([a-z0-9-]+)`/gm)].map((m) => m[1]));

  const anchorOf = (type: string | undefined) => type?.split("#")[1];

  it("has parsed the catalogue at all", () => {
    // Guards against a path or format change silently emptying the set, which would make every
    // assertion below vacuously pass.
    expect(documented.size).toBeGreaterThan(10);
  });

  // Framework-raised statuses, enumerated from the table the filter actually uses rather than
  // from a copy, so adding a status without documenting it fails here.
  it.each(Object.keys(CODE_BY_STATUS).map(Number))("documents the code for HTTP %i", (status) => {
    const { body } = capture(new HttpException("provoked", status));
    const anchor = anchorOf(body?.type);
    expect(anchor, `no anchor derived from type ${body?.type}`).toBeDefined();
    expect(
      documented.has(anchor!),
      `problems.md has no "### \`${anchor}\`" heading for code ${body?.code} (HTTP ${status})`,
    ).toBe(true);
  });

  // Domain errors, each constructed the way callers construct it.
  const domainErrors = [
    new TenantNotFoundError("nope"),
    new TenantAlreadyExistsError("acme"),
    new EmailAlreadyRegisteredError(),
    new InvalidCredentialsError(),
    new InvalidAccessTokenError(),
    new CrossTenantTokenError(),
    new ControlPlaneUnauthorizedError(),
    new TooManyRequestsError(1),
    new ValidationFailedError([{ detail: "slug must be lowercase", pointer: "#/slug" }]),
  ];

  it.each(domainErrors.map((e) => [e.constructor.name, e] as const))(
    "documents %s",
    (_name, error) => {
      const { body } = capture(error);
      const anchor = anchorOf(body?.type);
      expect(
        documented.has(anchor!),
        `problems.md has no "### \`${anchor}\`" heading for code ${body?.code}`,
      ).toBe(true);
    },
  );

  it("documents the catch-all used for an unknown throw", () => {
    const { body } = capture(new Error("something nobody mapped"));
    expect(body?.code).toBe("INTERNAL_ERROR");
    expect(documented.has(anchorOf(body?.type)!)).toBe(true);
  });
});
