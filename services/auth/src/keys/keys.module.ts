import { Global, Module } from "@nestjs/common";
import { JwksController } from "./jwks.controller";
import { KeyRegistryService } from "./key-registry.service";

/**
 * Global for the same reason as TenancyModule and AuthModule: TokenService needs the registry, and
 * requiring every module that touches auth to import this one is the ceremony the composed
 * decorator exists to remove.
 */
@Global()
@Module({
  controllers: [JwksController],
  providers: [KeyRegistryService],
  exports: [KeyRegistryService],
})
export class KeysModule {}
