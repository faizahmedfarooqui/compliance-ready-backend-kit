import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

/**
 * Documentation-only mirrors of the wire contract.
 *
 * These exist because the real definitions in @compliance-kit/common are framework-free interfaces, and
 * a TypeScript interface leaves nothing behind at runtime for the OpenAPI generator to read. Rather
 * than put Nest decorators on the shared package, which would make every consumer of the contract
 * depend on Nest, the shapes are restated here as classes.
 *
 * Restating anything invites drift, so the risk is named rather than ignored: if `ProblemDetails` or
 * `SuccessEnvelope` in packages/common changes and these do not, the published spec becomes wrong while
 * every test still passes. The mitigation is that the smoke test asserts the real response shape over
 * the wire, so a change in the contract fails there even though it cannot fail here.
 */

export class ResponseMetaSchema {
  @ApiPropertyOptional({
    description: "Human-readable note about the outcome. Not an error channel.",
  })
  message?: string;

  @ApiPropertyOptional({
    description: "Total matching records, which may exceed the number returned in `data`.",
    example: 412,
  })
  totalCount?: number;

  @ApiPropertyOptional({
    description:
      "Opaque pagination cursor. Null explicitly means there are no more in this direction.",
    nullable: true,
  })
  nextItem?: string | null;

  @ApiPropertyOptional({ nullable: true })
  prevItem?: string | null;
}

/**
 * The shape of EVERY 2xx body.
 *
 * `data` is deliberately left untyped here and filled in per route by the `ApiEnvelope` helper, which
 * composes this schema with the concrete resource. Handlers return the bare resource and an interceptor
 * adds the wrapper, so without that helper the generated spec would document the resource at the top
 * level and be wrong about every successful response in the API.
 */
export class SuccessEnvelopeSchema {
  @ApiProperty({
    example: true,
    description:
      "Always true. Errors are served as RFC 9457 problem details and never reach this shape, " +
      "so `success` is a valid discriminator on any response body.",
  })
  success!: boolean;

  @ApiProperty({ description: "The resource itself, unwrapped." })
  data!: unknown;

  @ApiProperty({ type: ResponseMetaSchema })
  meta!: ResponseMetaSchema;
}

/** One field-level validation failure. */
export class FieldProblemSchema {
  @ApiProperty({
    example: "slug must be lowercase, start with a letter, and use only a-z, 0-9, hyphen",
  })
  message!: string;

  @ApiProperty({
    example: "#/slug",
    description: "JSON Pointer (RFC 6901) into the request body.",
  })
  pointer!: string;
}

/**
 * The shape of EVERY error body, served as `application/problem+json` per RFC 9457.
 *
 * Documented as one schema for every status because that is genuinely how the API behaves: a single
 * exception filter renders all of them, so a client writes one error handler rather than branching on
 * status to guess the shape.
 */
export class ProblemDetailsSchema {
  @ApiProperty({
    example: false,
    description:
      "Always false. The mirror of `success` on the envelope, so one check works on any body.",
  })
  success!: boolean;

  @ApiProperty({
    example:
      "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/docs/problems.md#tenant-not-found",
    description:
      "URI identifying the problem TYPE (RFC 9457 s3.1.1). Dereferencing it yields documentation " +
      "for this exact problem, in docs/problems.md.",
  })
  type!: string;

  @ApiProperty({
    example: "Unknown or inactive tenant",
    description:
      "Short summary of the problem type (s3.1.3). Stable per type, and never interpolates request data.",
  })
  title!: string;

  @ApiProperty({ example: 404, description: "The HTTP status, repeated in the body (s3.1.2)." })
  status!: number;

  @ApiProperty({
    example: "Unknown or inactive tenant: acme",
    description: "Explanation of THIS occurrence (s3.1.4). Where request-specific detail belongs.",
  })
  detail!: string;

  @ApiProperty({
    example: "urn:uuid:0b3f2c1e-8a4d-4f9b-9c2e-1d5a7f6b3c8e",
    description: "Identifies this one occurrence (s3.1.5), as a urn:uuid.",
  })
  instance!: string;

  @ApiProperty({
    example: "TENANT_NOT_FOUND",
    description:
      "Stable machine-readable code. This, not `title`, is what a client should branch on.",
  })
  code!: string;

  @ApiProperty({
    example: "0b3f2c1e-8a4d-4f9b-9c2e-1d5a7f6b3c8e",
    description:
      "The occurrence id again, unwrapped, so a user can quote it without parsing a URI.",
  })
  traceId!: string;

  @ApiPropertyOptional({
    type: [FieldProblemSchema],
    description: "Present only on a 422. One entry per invalid field.",
  })
  errors?: FieldProblemSchema[];
}

/** A provisioned tenant. */
export class TenantSchema {
  @ApiProperty({ example: "9f1c2b7e-4d3a-4b8f-9e2c-5a6d7f8b9c01", format: "uuid" })
  id!: string;

  @ApiProperty({ example: "acme" })
  slug!: string;

  @ApiProperty({
    example: "tenant_acme",
    description: "The name of this tenant's dedicated database on the tenant cluster.",
  })
  databaseName!: string;

  @ApiProperty({ enum: ["provisioning", "active", "suspended"], example: "active" })
  status!: string;
}

export class AccessTokenSchema {
  @ApiProperty({
    description:
      "A nested JWT: the claims are signed (JWS, ES256) and that token is then encrypted (JWE, " +
      "A256KW + A256GCM), so it has FIVE dot-separated segments and its payload cannot be read in a " +
      "JWT decoder. That is deliberate: the claims carry the tenant id, user id, roles and " +
      "permissions, and an unencrypted token discloses all of it to whoever holds it, including the " +
      "end user. Inspect one you hold the keys for with `pnpm keys:decode <token>`.",
    example: "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiSldUIiwia2lkIjoiLi4uIn0.…",
  })
  accessToken!: string;
}

export class RegisteredUserSchema {
  @ApiProperty({ format: "uuid" })
  id!: string;

  @ApiProperty({ example: "user@acme.example" })
  email!: string;
}

export class UserSchema {
  @ApiProperty({ format: "uuid" })
  id!: string;

  @ApiProperty({ example: "user@acme.example" })
  email!: string;

  @ApiProperty({ enum: ["active", "disabled"], example: "active" })
  status!: string;

  @ApiProperty({ format: "date-time" })
  createdAt!: string;
}
