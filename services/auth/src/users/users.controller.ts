import { Controller, Get } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { PERMISSION_KEYS } from "@compliance-kit/common";
import { TenantAuthenticated } from "../rbac/tenant-authenticated.decorator";
import { ApiCommonErrors, ApiEnvelope, ApiProblem } from "../docs/api-envelope.decorator";
import { UserSchema } from "../docs/schemas";
import { UsersService } from "./users.service";

@ApiTags("users")
@ApiBearerAuth("accessToken")
@Controller("users")
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @TenantAuthenticated(PERMISSION_KEYS.usersRead)
  @ApiOperation({
    summary: "List users in the current tenant",
    description:
      "Requires the `users:read` permission. Reads from the tenant's OWN database, resolved from the " +
      "`x-tenant-id` header, so there is no cross-tenant query to get wrong.\n\n" +
      "A token issued for one tenant presented with a different tenant in the header is rejected as " +
      "`CROSS_TENANT_TOKEN`, in the same step as authentication. Database-per-tenant already routes the " +
      "query to the right place, so no data would cross; the rejection is because the caller would " +
      "otherwise be acting inside a tenant they hold no account in, carrying the other tenant's " +
      "permissions.",
  })
  @ApiEnvelope(UserSchema, { isArray: true, description: "Users in this tenant." })
  @ApiProblem(401, "Missing, expired, or invalid access token.", "INVALID_ACCESS_TOKEN")
  @ApiProblem(403, "The token is valid but lacks the `users:read` permission.", "FORBIDDEN")
  @ApiCommonErrors()
  list() {
    return this.users.list();
  }
}
