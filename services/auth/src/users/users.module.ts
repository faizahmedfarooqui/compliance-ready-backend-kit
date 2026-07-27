import { Module } from "@nestjs/common";
import { UsersController } from "./users.controller";
import { UsersService } from "./users.service";

// TenancyModule and AuthModule are @Global(), so the guards applied by
// @TenantAuthenticated resolve here without importing anything.
@Module({
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
