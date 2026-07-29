import { Module } from "@nestjs/common";
import { CoreModule } from "./core/core.module";
import { TenancyModule } from "./tenancy/tenancy.module";
import { AuthModule } from "./auth/auth.module";
import { UsersModule } from "./users/users.module";
import { TenantsModule } from "./tenants/tenants.module";
import { HealthModule } from "./health/health.module";
import { KeysModule } from "./keys/keys.module";
import { RateLimitModule } from "./ratelimit/ratelimit.module";

@Module({
  imports: [
    CoreModule,
    // Before the feature modules so its global guard is registered first: an unauthenticated
    // flood should be rejected by the cheapest check available, not after a database lookup.
    RateLimitModule,
    KeysModule,
    TenancyModule,
    AuthModule,
    UsersModule,
    TenantsModule,
    HealthModule,
  ],
})
export class AppModule {}
