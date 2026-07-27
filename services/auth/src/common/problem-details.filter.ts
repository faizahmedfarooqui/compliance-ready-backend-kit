import { randomUUID } from "node:crypto";
import {
  ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Inject,
  Logger,
} from "@nestjs/common";
import {
  CrossTenantTokenError,
  DomainError,
  EmailAlreadyRegisteredError,
  InvalidAccessTokenError,
  InvalidCredentialsError,
  TenantAlreadyExistsError,
  TenantContextMissingError,
  TenantNotFoundError,
  ValidationFailedError,
  type ProblemDetails,
} from "@compliance-kit/common";
import type { AppConfig } from "@compliance-kit/config";
import type { FastifyReply, FastifyRequest } from "fastify";
import { CONFIG } from "../core/tokens";

/**
 * Renders EVERY error as RFC 9457 Problem Details.
 *
 * `@Catch()` with no argument is deliberate. Previously only DomainError was handled, which
 * left three different error shapes on the wire: this filter's, the ValidationPipe's, and
 * Nest's built-in fallback for things like an unmatched route. A client could not branch on
 * any of them reliably, because `error` was a machine code in one and a human phrase in the
 * others. One filter, one shape.
 *
 * The other reason to catch everything: an unexpected throw previously reached Nest's default
 * handler. Here it is logged with its stack server-side and answered with a body that contains
 * nothing but a status and a trace id, so a driver message or a SQL fragment cannot escape in
 * a response. That is a disclosure control, not just tidiness.
 */
const STATUS_BY_ERROR: ReadonlyArray<[new (...args: never[]) => DomainError, HttpStatus]> = [
  [InvalidCredentialsError, HttpStatus.UNAUTHORIZED],
  [InvalidAccessTokenError, HttpStatus.UNAUTHORIZED],
  [CrossTenantTokenError, HttpStatus.UNAUTHORIZED],
  [TenantNotFoundError, HttpStatus.NOT_FOUND],
  [TenantAlreadyExistsError, HttpStatus.CONFLICT],
  [EmailAlreadyRegisteredError, HttpStatus.CONFLICT],
  // Well-formed JSON, unacceptable values. A malformed body never reaches here: Fastify
  // rejects it with 400 first, so 400 and 422 stay meaningfully different for clients.
  [ValidationFailedError, HttpStatus.UNPROCESSABLE_ENTITY],
  [TenantContextMissingError, HttpStatus.BAD_REQUEST],
];

@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  private readonly logger = new Logger(ProblemDetailsFilter.name);

  constructor(@Inject(CONFIG) private readonly config: AppConfig) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const reply = http.getResponse<FastifyReply>();
    const request = http.getRequest<FastifyRequest>();

    // Identifies this one occurrence. Goes in `instance` as a URN, per RFC 9457 s3.1.5, and
    // again as a bare `traceId` so a user can quote it without parsing a URI.
    const traceId = randomUUID();
    const problem = this.toProblem(exception, traceId, request.url);

    if (problem.status >= 500) {
      // The only place the real cause is recorded. Never sent to the client.
      this.logger.error(
        `${request.method} ${request.url} failed [traceId=${traceId}]: ${describe(exception)}`,
        exception instanceof Error ? exception.stack : undefined,
      );
    }

    void reply
      .status(problem.status)
      // RFC 9457 s3: the media type for this format.
      .header("content-type", "application/problem+json; charset=utf-8")
      .send(problem);
  }

  /**
   * Member order matters only for whoever reads the raw body, but that is worth something:
   * `success` first because it is the discriminator a client checks, then `type`, `title`,
   * `status`, `detail` in the order RFC 9457 §3.1 introduces them, then the identifiers.
   */
  private toProblem(exception: unknown, traceId: string, path: string): ProblemDetails {
    if (exception instanceof DomainError) {
      const match = STATUS_BY_ERROR.find(([type]) => exception instanceof type);
      return {
        success: false,
        type: this.typeUri(exception.code),
        title: exception.title,
        status: match?.[1] ?? HttpStatus.BAD_REQUEST,
        detail: exception.message,
        instance: `urn:uuid:${traceId}`,
        code: exception.code,
        traceId,
        ...(exception instanceof ValidationFailedError ? { errors: exception.errors } : {}),
      };
    }

    // Nest's own exceptions, including the 404 for an unmatched route, the 400 Fastify raises
    // for an unparseable body, and anything a guard throws directly. Normalised into the same
    // shape rather than left to the default handler.
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const code = CODE_BY_STATUS[status] ?? `HTTP_${status}`;
      return {
        success: false,
        type: this.typeUri(code),
        title: TITLE_BY_STATUS[status] ?? `HTTP ${status}`,
        status,
        detail: httpDetail(exception, path),
        instance: `urn:uuid:${traceId}`,
        code,
        traceId,
      };
    }

    // Unknown. Deliberately says nothing about the cause.
    return {
      success: false,
      type: this.typeUri("INTERNAL_ERROR"),
      title: "Internal server error",
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      detail: `An unexpected error occurred. Quote traceId ${traceId} when reporting it.`,
      instance: `urn:uuid:${traceId}`,
      code: "INTERNAL_ERROR",
      traceId,
    };
  }

  /** e.g. TENANT_NOT_FOUND -> https://.../docs/problems.md#tenant-not-found */
  private typeUri(code: string): string {
    return `${this.config.problemTypeBaseUri}#${code.toLowerCase().replaceAll("_", "-")}`;
  }
}

/**
 * Codes and titles for framework-raised statuses, so a client branching on `code` gets
 * something stable and a human reading `title` gets a sentence rather than "HTTP 400".
 * Anything not listed falls back to `HTTP_<status>`, which is a signal to add it here.
 */
const CODE_BY_STATUS: Readonly<Record<number, string>> = {
  [HttpStatus.BAD_REQUEST]: "MALFORMED_REQUEST",
  [HttpStatus.NOT_FOUND]: "ROUTE_NOT_FOUND",
  [HttpStatus.METHOD_NOT_ALLOWED]: "METHOD_NOT_ALLOWED",
  [HttpStatus.NOT_ACCEPTABLE]: "NOT_ACCEPTABLE",
  [HttpStatus.PAYLOAD_TOO_LARGE]: "PAYLOAD_TOO_LARGE",
  [HttpStatus.UNSUPPORTED_MEDIA_TYPE]: "UNSUPPORTED_MEDIA_TYPE",
  [HttpStatus.TOO_MANY_REQUESTS]: "TOO_MANY_REQUESTS",
};

const TITLE_BY_STATUS: Readonly<Record<number, string>> = {
  [HttpStatus.BAD_REQUEST]: "Malformed request",
  [HttpStatus.NOT_FOUND]: "Resource not found",
  [HttpStatus.METHOD_NOT_ALLOWED]: "Method not allowed",
  [HttpStatus.NOT_ACCEPTABLE]: "Not acceptable",
  [HttpStatus.PAYLOAD_TOO_LARGE]: "Request body too large",
  [HttpStatus.UNSUPPORTED_MEDIA_TYPE]: "Unsupported media type",
  [HttpStatus.TOO_MANY_REQUESTS]: "Too many requests",
};

/**
 * Pull a safe explanation out of a Nest HttpException. Its response body may be a string or an
 * object with a `message` that is itself a string or an array, so this normalises without
 * trusting the shape, and never falls back to anything but a generic sentence.
 */
function httpDetail(exception: HttpException, path: string): string {
  const body = exception.getResponse();
  if (typeof body === "string") return body;
  if (typeof body === "object" && body !== null && "message" in body) {
    const message = (body as { message: unknown }).message;
    if (typeof message === "string") return message;
    if (Array.isArray(message)) return message.filter((m) => typeof m === "string").join("; ");
  }
  return `Request to ${path} could not be completed.`;
}

function describe(exception: unknown): string {
  if (exception instanceof Error) return `${exception.name}: ${exception.message}`;
  return String(exception);
}
