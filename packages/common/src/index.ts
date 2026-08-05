// Shared domain types and errors used across services and packages.

/** Identifier for a tenant (a customer/company). Opaque string, never reused. */
export type TenantId = string;

export type TenantStatus = "provisioning" | "active" | "suspended";

/** A resolved tenant, loaded from the master registry. */
export interface Tenant {
  id: TenantId;
  slug: string;
  /** The name of this tenant's dedicated database on the tenant cluster. */
  databaseName: string;
  status: TenantStatus;
}

/** Claims carried in an access token. Kept small and tenant-scoped. */
export interface AccessTokenClaims {
  sub: string; // user id (within the tenant)
  tid: TenantId; // tenant id
  roles: string[];
  permissions: string[];
}

// ---------------------------------------------------------------------------
// RBAC catalogue
//
// Permission keys are declared here, in one place, so the strings used by
// @RequirePermissions on a controller and the rows seeded into a new tenant's database
// cannot drift apart. A permission that is checked but never seeded is a permanent 403;
// one that is seeded but never checked is a control nobody enforces. Both are the kind
// of thing an access-control review (HIPAA 164.312(a)(1), PCI Req 7, SOC 2 CC6.3) is
// meant to surface, so keep this list and the decorators in step.
// ---------------------------------------------------------------------------

export const PERMISSION_KEYS = {
  usersRead: "users:read",
  usersWrite: "users:write",
  rolesManage: "roles:manage",
} as const;

export type PermissionKey = (typeof PERMISSION_KEYS)[keyof typeof PERMISSION_KEYS];

export interface PermissionDefinition {
  key: PermissionKey;
  description: string;
}

/** Seeded into every new tenant database at provisioning time. */
export const DEFAULT_PERMISSIONS: readonly PermissionDefinition[] = [
  { key: PERMISSION_KEYS.usersRead, description: "List and view users in this tenant" },
  {
    key: PERMISSION_KEYS.usersWrite,
    description: "Create, modify, and disable users in this tenant",
  },
  {
    key: PERMISSION_KEYS.rolesManage,
    description: "Create roles and change their permission grants",
  },
];

/**
 * The one role seeded into a new tenant. It holds every permission in
 * DEFAULT_PERMISSIONS and is granted to the tenant's initial administrator, created
 * during provisioning. Everything beyond it is expected to be defined per deployment:
 * this is a starting point for least privilege, not a finished role model.
 */
export const TENANT_ADMIN_ROLE_NAME = "tenant-admin";
export const TENANT_ADMIN_ROLE_DESCRIPTION =
  "Full administrative access within this tenant. Seeded at provisioning and granted " +
  "to the tenant's initial administrator.";

// ---------------------------------------------------------------------------
// The wire contract
//
// Both shapes live here, framework-free, so that a generated SDK and any future service can
// import the same definitions rather than re-describing them.
// ---------------------------------------------------------------------------

/**
 * An error body, per RFC 9457 (Problem Details for HTTP APIs). Served as
 * `application/problem+json`.
 *
 * Every field below is exactly as the RFC defines it. Read §3.1 before changing any of them,
 * particularly the difference between `title` (stable per problem type) and `detail`
 * (specific to this one occurrence).
 */
export interface ProblemDetails {
  /**
   * Extension member (§3.2). Always `false`, and the mirror of `SuccessEnvelope.success`.
   *
   * It exists so that `success` actually discriminates. Carried only by the success envelope it
   * would be a field that is always `true`, which tells a client nothing; present on both
   * shapes it makes `body.success` a valid check on ANY response, which is the point of asking
   * for it. RFC 9457 §3.2 permits extension members, and requires consumers to ignore ones they
   * do not recognise, so this costs nothing for a generic problem-details client.
   */
  success: false;
  /**
   * URI reference identifying the problem TYPE (§3.1.1). Dereferencing it should yield
   * human-readable documentation, which is why it points into problems.md. The RFC
   * recommends absolute URIs, so the base is configurable rather than a bare relative path.
   */
  type: string;
  /** Short, stable summary of the problem type (§3.1.3). Never occurrence-specific. */
  title: string;
  /**
   * The HTTP status code (§3.1.2). Advisory only, and the RFC requires the real response to
   * use the same code, so this is always derived from the actual status rather than set apart.
   */
  status: number;
  /** Human-readable explanation of THIS occurrence (§3.1.4). */
  detail: string;
  /**
   * URI reference identifying this specific occurrence (§3.1.5). A `urn:uuid:` here, because
   * the RFC permits a non-dereferenceable instance to act purely as a unique occurrence id,
   * and that is what correlates a client's report with a server log line.
   */
  instance: string;
  /** Extension member (§3.2): the stable machine-readable code to branch on. */
  code: string;
  /** Extension member (§3.2): the occurrence id again, unwrapped, for support workflows. */
  traceId: string;
  /** Extension member (§3.2): present only on validation failures. */
  errors?: FieldProblem[];
}

/**
 * Optional metadata accompanying a successful response. Open-ended by design: the listed
 * fields are the common ones, and problem-specific additions are allowed.
 */
export interface ResponseMeta {
  /** Human-readable note about the outcome. Not an error channel. */
  message?: string;
  /** Total matching records, which may exceed the number returned. */
  totalCount?: number;
  /** Opaque cursors for pagination. Null explicitly means "no more in this direction". */
  nextItem?: string | null;
  prevItem?: string | null;
  [key: string]: unknown;
}

/** Every 2xx response body. */
export interface SuccessEnvelope<T> {
  /**
   * Always true. Failures are served as RFC 9457 Problem Details and never reach this shape,
   * so this exists to give clients one uniform check without branching on the status line,
   * and to leave room for a partial-success response later.
   */
  success: true;
  data: T;
  meta: ResponseMeta;
}

/** Marker for a handler return value that carries its own `meta`. See `withMeta`. */
const META_MARKER = Symbol.for("compliance-kit.response-meta");

export interface DataWithMeta<T> {
  [META_MARKER]: true;
  data: T;
  meta: ResponseMeta;
}

/**
 * Attach `meta` to a handler's return value.
 *
 * Handlers normally return a bare resource and the envelope is added for them. Use this only
 * when a route needs to say something extra: `return withMeta(users, { totalCount: 412 })`.
 */
export function withMeta<T>(data: T, meta: ResponseMeta): DataWithMeta<T> {
  return { [META_MARKER]: true, data, meta };
}

export function hasMeta<T>(value: unknown): value is DataWithMeta<T> {
  return typeof value === "object" && value !== null && META_MARKER in value;
}

// ---------------------------------------------------------------------------
// Domain errors
// ---------------------------------------------------------------------------

/**
 * Base class for errors we deliberately surface to callers (safe messages).
 *
 * Carries `title` separately from `message` because they serve different jobs in RFC 9457.
 * `title` is a summary of the problem TYPE and "SHOULD NOT change from occurrence to
 * occurrence" (§3.1.3), so it must not interpolate anything. `message` becomes `detail`, the
 * "human-readable explanation specific to this occurrence" (§3.1.4), and is where the tenant
 * slug or field name belongs.
 */
export class DomainError extends Error {
  constructor(
    /** Stable, per-type summary. Never interpolate request data into this. */
    readonly title: string,
    /** Occurrence-specific explanation. Becomes RFC 9457 `detail`. */
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class TenantNotFoundError extends DomainError {
  constructor(tenant: string) {
    super(
      "Unknown or inactive tenant",
      `Unknown or inactive tenant: ${tenant}`,
      "TENANT_NOT_FOUND",
    );
  }
}

export class TenantContextMissingError extends DomainError {
  constructor() {
    super(
      "No tenant resolved for this request",
      "No tenant resolved for this request. Supply the x-tenant-id header.",
      "TENANT_CONTEXT_MISSING",
    );
  }
}

export class TenantAlreadyExistsError extends DomainError {
  constructor(slug: string) {
    super(
      "Tenant already exists",
      `A tenant with slug "${slug}" already exists`,
      "TENANT_ALREADY_EXISTS",
    );
  }
}

export class EmailAlreadyRegisteredError extends DomainError {
  constructor() {
    super(
      "Email already registered",
      "That email address is already registered",
      "EMAIL_ALREADY_REGISTERED",
    );
  }
}

export class InvalidCredentialsError extends DomainError {
  constructor() {
    super("Invalid credentials", "Invalid credentials", "INVALID_CREDENTIALS");
  }
}

/**
 * The access token is missing, malformed, expired, or failed either layer of verification.
 * Deliberately one error for every cause: telling a caller which check failed tells an
 * attacker which part of a forged token to fix next.
 */
export class InvalidAccessTokenError extends DomainError {
  constructor() {
    super(
      "Missing or invalid access token",
      "Missing or invalid access token",
      "INVALID_ACCESS_TOKEN",
    );
  }
}

/**
 * The access token authenticates a user of a different tenant than the one the request
 * is addressed to. Database-per-tenant stops such a request from reading the token
 * holder's OWN tenant data, but on its own it does not stop the holder from acting
 * inside the addressed tenant, which is what this rejects.
 */
export class CrossTenantTokenError extends DomainError {
  constructor() {
    super(
      "Access token is not valid for the requested tenant",
      "Access token is not valid for the requested tenant",
      "CROSS_TENANT_TOKEN",
    );
  }
}

/** One field-level validation failure, shaped as RFC 9457 §3.2's `errors` extension. */
export interface FieldProblem {
  /** Why this field was rejected. */
  detail: string;
  /** JSON Pointer (RFC 6901) into the request body, e.g. "#/slug". */
  pointer: string;
}

/**
 * Request body failed DTO validation. Well-formed JSON with unacceptable values, which is
 * why it maps to 422 rather than 400: a malformed body never reaches this point, Fastify
 * rejects it as 400 first. The RFC 9457 validation illustration (§3.2) uses 422 the same way.
 */
export class ValidationFailedError extends DomainError {
  constructor(readonly errors: FieldProblem[]) {
    super("Request validation failed", "One or more fields are invalid", "VALIDATION_FAILED");
  }
}

/**
 * A control-plane route was called without a valid credential. Maps to 401.
 *
 * One error for "no key" and "wrong key" on purpose. Separate messages would tell a prober whether
 * the route is protected and whether their header shape was accepted, which is help they should not
 * get while guessing a credential.
 */
export class ControlPlaneUnauthorizedError extends DomainError {
  constructor() {
    super(
      "Control-plane authorization required",
      "This endpoint requires a valid control-plane credential",
      "CONTROL_PLANE_UNAUTHORIZED",
    );
  }
}

/**
 * The caller has exceeded a rate limit. Maps to 429.
 *
 * Carries `retryAfterSeconds` because the number has to survive the trip to the exception filter,
 * which is what writes the `Retry-After` header. Rounded UP to a whole second and floored at 1 by the
 * constructor rather than by the caller: RFC 9110 §10.2.3 defines `delay-seconds` as a non-negative
 * integer, so `Retry-After: 0.4` is malformed, and a rounded-down 0 tells a client to retry
 * immediately, which is precisely the opposite of the message.
 *
 * The detail deliberately does not say WHICH limit was hit or how many attempts remain. On the login
 * route that would confirm to an attacker that an account exists and is worth continuing against,
 * which is the same reasoning that makes InvalidCredentialsError say nothing.
 */
export class TooManyRequestsError extends DomainError {
  readonly retryAfterSeconds: number;

  constructor(retryAfterMs: number) {
    super("Too many requests", "Too many requests. Retry later.", "TOO_MANY_REQUESTS");
    this.retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  }
}
