import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { FastifyAdapter, type NestFastifyApplication } from "@nestjs/platform-fastify";
import { Logger, ValidationPipe } from "@nestjs/common";
import { loadConfig, loadLocalDotenv } from "@compliance-kit/config";
import { AppModule } from "./app.module";
import { validationExceptionFactory } from "./common/validation-exception.factory";

async function bootstrap(): Promise<void> {
  // Local development convenience; a no-op when NODE_ENV=production, where config is
  // expected to arrive from KMS / Secrets Manager. See @compliance-kit/config.
  loadLocalDotenv();
  const config = loadConfig();

  const app = await NestFactory.create<NestFastifyApplication>(AppModule, new FastifyAdapter());

  app.setGlobalPrefix("api");
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
  // Lets CoreModule close its database pools on SIGTERM instead of dropping them.
  app.enableShutdownHooks();

  await app.listen(config.port, "0.0.0.0");
  new Logger("bootstrap").log(`auth-service listening on :${config.port}`);
}

void bootstrap();
