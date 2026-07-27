import { describe, expect, it } from "vitest";
import { BadRequestException, HttpStatus, NotFoundException } from "@nestjs/common";
import type { ArgumentsHost } from "@nestjs/common";
import type { AppConfig } from "@compliance-kit/config";
import {
  CrossTenantTokenError,
  EmailAlreadyRegisteredError,
  InvalidAccessTokenError,
  InvalidCredentialsError,
  TenantAlreadyExistsError,
  TenantNotFoundError,
  ValidationFailedError,
  type ProblemDetails,
} from "@compliance-kit/common";
import { ProblemDetailsFilter } from "./problem-details.filter";

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
