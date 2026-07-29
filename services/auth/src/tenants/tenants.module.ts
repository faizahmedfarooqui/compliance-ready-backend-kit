import { Module } from "@nestjs/common";
import { TenantsController } from "./tenants.controller";
import { TenantsService } from "./tenants.service";
import { ControlPlaneGuard } from "./control-plane.guard";

@Module({
  controllers: [TenantsController],
  providers: [TenantsService, ControlPlaneGuard],
})
export class TenantsModule {}
