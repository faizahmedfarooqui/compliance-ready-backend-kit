import { Controller, Get } from "@nestjs/common";
import { PERMISSION_KEYS } from "@compliance-kit/common";
import { TenantAuthenticated } from "../rbac/tenant-authenticated.decorator";
import { UsersService } from "./users.service";

@Controller("users")
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @TenantAuthenticated(PERMISSION_KEYS.usersRead)
  list() {
    return this.users.list();
  }
}
