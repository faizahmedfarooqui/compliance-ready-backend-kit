import { applyDecorators, type Type } from "@nestjs/common";
import { ApiExtraModels, ApiResponse, getSchemaPath } from "@nestjs/swagger";
import { ProblemDetailsSchema, SuccessEnvelopeSchema } from "./schemas";

/**
 * Documents a success response in the shape the client actually receives.
 *
 * Needed because handlers return a bare resource and ResponseEnvelopeInterceptor wraps it in
 * `{ success, data, meta }` on the way out. The OpenAPI generator reads the handler's return type and
 * knows nothing about interceptors, so the default output documents the resource at the top level. That
 * is not a cosmetic inaccuracy: a generated client would deserialise `{ success, data, meta }` into a
 * model expecting `{ id, slug, ... }` and every field would come back undefined.
 *
 * `allOf` composes the envelope with the concrete resource rather than redefining it per route, so the
 * envelope is described once and `data` is narrowed per endpoint.
 */
export function ApiEnvelope<TModel extends Type<unknown>>(
  model: TModel,
  options: { status?: number; description?: string; isArray?: boolean } = {},
): MethodDecorator & ClassDecorator {
  const { status = 200, description, isArray = false } = options;
  const dataSchema = isArray
    ? { type: "array" as const, items: { $ref: getSchemaPath(model) } }
    : { $ref: getSchemaPath(model) };

  return applyDecorators(
    ApiExtraModels(SuccessEnvelopeSchema, model),
    ApiResponse({
      status,
      description,
      schema: {
        allOf: [
          { $ref: getSchemaPath(SuccessEnvelopeSchema) },
          { properties: { data: dataSchema }, required: ["data"] },
        ],
      },
    }),
  );
}

/**
 * Documents one error response as RFC 9457 problem details.
 *
 * Every error in this API has the same body, so the schema is shared and only the description differs.
 * Worth attaching explicitly rather than leaving to a generic "400 Bad Request": the useful thing for a
 * client is the `code` it can branch on, and that only appears if someone writes it down.
 */
export function ApiProblem(
  status: number,
  description: string,
  code?: string,
): MethodDecorator & ClassDecorator {
  return applyDecorators(
    ApiExtraModels(ProblemDetailsSchema),
    ApiResponse({
      status,
      description: code ? `${description} (\`code\`: \`${code}\`)` : description,
      content: {
        // The registered media type for this format (RFC 9457 s3), not application/json. A client that
        // negotiates on content type has to see the real one or it will not parse the body.
        "application/problem+json": { schema: { $ref: getSchemaPath(ProblemDetailsSchema) } },
      },
    }),
  );
}

/**
 * The three errors that can reach almost any route, so they are documented once and applied together.
 *
 * 429 is here rather than only on the strict routes because the per-client budget applies globally: any
 * endpoint can return it, and a client that has not handled it will retry immediately and make things
 * worse.
 */
export function ApiCommonErrors(): MethodDecorator & ClassDecorator {
  return applyDecorators(
    ApiProblem(422, "Well-formed JSON with unacceptable values.", "VALIDATION_FAILED"),
    ApiProblem(
      429,
      "Rate limit exceeded. Carries `Retry-After` in whole seconds and `Cache-Control: no-store`.",
      "TOO_MANY_REQUESTS",
    ),
    ApiProblem(
      500,
      "Unexpected fault. The body carries a `traceId` and nothing else.",
      "INTERNAL_ERROR",
    ),
  );
}
