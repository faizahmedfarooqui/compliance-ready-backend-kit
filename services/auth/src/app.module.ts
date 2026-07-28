import { Module } from "@nestjs/common";
import { CoreModule } from "./core/core.module";
import { TenancyModule } from "./tenancy/tenancy.module";
import { AuthModule } from "./auth/auth.module";
import { UsersModule } from "./users/users.module";
import { TenantsModule } from "./tenants/tenants.module";
import { HealthModule } from "./health/health.module";
import { KeysModule } from "./keys/keys.module";

@Module({
  imports: [
    CoreModule,
    KeysModule,
    TenancyModule,
    AuthModule,
    UsersModule,
    TenantsModule,
    HealthModule,
  ],
})
export class AppModule {}
