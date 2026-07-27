import { Body, Controller, Post, UseGuards } from "@nestjs/common";
import { TenantGuard } from "../tenancy/tenant.guard";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";

// Every route here requires a resolved tenant (x-tenant-id header): users live in
// the tenant's own database, so we must know which database before we can touch them.
@Controller("auth")
@UseGuards(TenantGuard)
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post("register")
  register(@Body() dto: RegisterDto): Promise<{ id: string; email: string }> {
    return this.auth.register(dto.email, dto.password);
  }

  @Post("login")
  login(@Body() dto: LoginDto): Promise<{ accessToken: string }> {
    return this.auth.login(dto.email, dto.password);
  }
}
