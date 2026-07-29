import { Logger } from "@nestjs/common";
import type { NestFastifyApplication } from "@nestjs/platform-fastify";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import type { AppConfig } from "@compliance-kit/config";
import {
  AccessTokenSchema,
  FieldProblemSchema,
  ProblemDetailsSchema,
  RegisteredUserSchema,
  ResponseMetaSchema,
  SuccessEnvelopeSchema,
  TenantSchema,
  UserSchema,
} from "./schemas";

/** Header the tenant is resolved from. Named here so the spec and the guard cannot disagree. */
const TENANT_HEADER = "x-tenant-id";

/**
 * Publishes the OpenAPI document and the browsable UI.
 *
 * Mounted OUTSIDE the `api` prefix, at `/docs`, for the same reason as the JWKS route: a documentation
 * page is not a versioned API resource, and burying it under the prefix that carries the API's routes
 * makes it look like one.
 */
export function setupOpenApi(app: NestFastifyApplication, config: AppConfig): void {
  const logger = new Logger("OpenAPI");

  if (!config.apiDocsEnabled) {
    logger.log("API docs are disabled (API_DOCS_ENABLED=false)");
    return;
  }

  /**
   * An OpenAPI document is a complete map of the attack surface: every route, every parameter, every
   * field and its constraints. That is exactly what it is for, and exactly why serving it publicly in
   * production deserves a decision rather than a default. Loud rather than silently overridden, because
   * the person who set the flag may not be the person reading the logs.
   */
  if (config.nodeEnv === "production") {
    logger.warn(
      "API docs are ENABLED in production. The document describes every route, parameter and " +
        "constraint in the service. Set API_DOCS_ENABLED=false unless this is deliberate.",
    );
  }

  const document = SwaggerModule.createDocument(
    app,
    new DocumentBuilder()
      .setTitle("compliance-ready-backend-kit")
      .setDescription(
        [
          "A NestJS + Postgres baseline built as a controls list, not a feature list.",
          "",
          "**Two things about this API that are unusual, and will break a client that assumes otherwise.**",
          "",
          "1. **Every success body is wrapped**: `{ success, data, meta }`. The resource is in `data`.",
          "   The one exception is `/.well-known/jwks.json`, which serves a bare JWK Set because",
          "   wrapping it would break every standard JWKS consumer.",
          "2. **Every error body is RFC 9457 problem details**, served as `application/problem+json`,",
          "   with a stable `code` to branch on and a `traceId` to quote in a support request. Both",
          "   bodies carry `success`, so it discriminates on any response.",
          "",
          "**Access tokens are nested JWTs**: signed with ES256, then encrypted with A256KW + A256GCM.",
          "Five segments, and the payload is not readable in a JWT decoder. That is deliberate: the",
          "claims carry the tenant id, user id, roles and permissions.",
          "",
          "**Most routes need a tenant.** Users live in their tenant's own database, so the service must",
          `know which database before it can touch them. Send \`${TENANT_HEADER}\` with a slug or a uuid.`,
          "",
          "Error catalogue: [docs/problems.md](https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/docs/problems.md).",
        ].join("\n"),
      )
      .setVersion(process.env.npm_package_version ?? "0.1.0")
      .setLicense(
        "MIT",
        "https://github.com/faizahmedfarooqui/compliance-ready-backend-kit/blob/main/LICENSE",
      )
      /**
       * Two bearer schemes, not one, because they are genuinely different credentials with different
       * blast radii. Collapsing them into a single "bearerAuth" would suggest a token that works on one
       * also works on the other, which is the confusion that leads to handing an operator credential to
       * a service that only needed to read users.
       */
      .addBearerAuth(
        {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWE",
          description:
            "A nested JWT from `POST /api/auth/login`. Identifies a user within one tenant, and is " +
            "rejected if presented with a different tenant in the header than the one it was issued for.",
        },
        "accessToken",
      )
      .addBearerAuth(
        {
          type: "http",
          scheme: "bearer",
          description:
            "The control-plane credential (`CONTROL_PLANE_API_KEY`). Authorises acting on the " +
            "DEPLOYMENT rather than inside a tenant, which today means creating tenants and therefore " +
            "databases. It authenticates the bearer and not a person, so it cannot attribute an action " +
            "to an operator.",
        },
        "controlPlane",
      )
      .addGlobalParameters({
        name: TENANT_HEADER,
        in: "header",
        required: false,
        description:
          "Which tenant the request acts inside. Accepts the slug or the uuid. Required by every route " +
          "that touches tenant data; ignored by the control plane and by /health.",
        schema: { type: "string", example: "acme" },
      })
      .addTag("auth", "Registration, login, and access tokens")
      .addTag("users", "Users within the current tenant")
      .addTag("tenants", "Control plane: provisioning. Requires the control-plane credential.")
      .addTag("health", "Liveness, and which build is actually running")
      .addTag("keys", "Published verification keys (JWKS)")
      .build(),
    {
      // Registered explicitly because they are referenced through `allOf` composition and `$ref` rather
      // than appearing as a handler's return type, so the generator never sees them by itself.
      extraModels: [
        SuccessEnvelopeSchema,
        ResponseMetaSchema,
        ProblemDetailsSchema,
        FieldProblemSchema,
        TenantSchema,
        AccessTokenSchema,
        RegisteredUserSchema,
        UserSchema,
      ],
    },
  );

  SwaggerModule.setup("docs", app, document, {
    jsonDocumentUrl: "docs/openapi.json",
    yamlDocumentUrl: "docs/openapi.yaml",
    swaggerOptions: {
      // Keeps a pasted credential across page reloads, so trying three endpoints does not mean
      // authorising three times.
      persistAuthorization: true,
      docExpansion: "list",
    },
  });

  logger.log(`API docs at /docs, document at /docs/openapi.json`);
}
