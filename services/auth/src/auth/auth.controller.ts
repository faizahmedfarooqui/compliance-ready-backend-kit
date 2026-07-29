import { Body, Controller, Ip, Post, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { TenantGuard } from "../tenancy/tenant.guard";
import { ApiCommonErrors, ApiEnvelope, ApiProblem } from "../docs/api-envelope.decorator";
import { AccessTokenSchema, RegisteredUserSchema } from "../docs/schemas";
import { RateLimit } from "../ratelimit/rate-limit.decorator";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";

// Every route here requires a resolved tenant (x-tenant-id header): users live in
// the tenant's own database, so we must know which database before we can touch them.
@ApiTags("auth")
@Controller("auth")
@UseGuards(TenantGuard)
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  /**
   * Stricter than the default budget because registering runs an Argon2id hash, which is expensive BY
   * DESIGN. That makes an unauthenticated route with no other cost a CPU amplifier: one cheap request
   * buys a large and deliberate amount of server work, so the property that protects stored passwords
   * is the property being abused.
   */
  @Post("register")
  @RateLimit({ limit: 10, windowMs: 60_000 })
  @ApiOperation({
    summary: "Register an unprivileged user in the current tenant",
    description:
      "The new user holds NO roles and therefore no permissions, so they can authenticate and do " +
      "nothing else until an administrator grants them a role. This route is unauthenticated, which is " +
      "why a tenant's first administrator is NOT created here: `pnpm db:seed:admin` does that, so " +
      "learning a tenant slug is not a way to claim the tenant.",
  })
  @ApiEnvelope(RegisteredUserSchema, { status: 201, description: "User created." })
  @ApiProblem(409, "That email is already registered in this tenant.", "EMAIL_ALREADY_REGISTERED")
  @ApiProblem(404, "The tenant in the header does not exist or is inactive.", "TENANT_NOT_FOUND")
  @ApiCommonErrors()
  register(@Body() dto: RegisterDto): Promise<{ id: string; email: string }> {
    return this.auth.register(dto.email, dto.password);
  }

  /**
   * Two separate controls apply here and they cover different things.
   *
   * This one bounds ATTEMPTS per address, because every attempt costs an Argon2id verification whether
   * the password is right or wrong, including for an address that is not registered (the decoy hash
   * exists precisely so it does). LoginThrottleService separately bounds FAILURES per account and per
   * address, which is what slows guessing. Neither substitutes for the other: an attempt limit alone
   * lets a distributed attacker guess indefinitely at a low rate, and a failure limit alone leaves the
   * CPU cost of the attempts unbounded.
   *
   * `@Ip()` resolves through Fastify's trustProxy handling rather than reading a header directly. See
   * `trustProxy` in @compliance-kit/config for why that setting has no safe default.
   */
  @Post("login")
  @RateLimit({ limit: 20, windowMs: 60_000 })
  @ApiOperation({
    summary: "Exchange credentials for an access token",
    description:
      "Two rate limits apply. This route allows 20 ATTEMPTS per minute per address, because every " +
      "attempt costs an Argon2id verification whether the password is right or wrong. Separately, " +
      "FAILED logins are counted per account and per address, and exceeding that returns 429 even for " +
      "the correct password. The failure count is cleared by a successful login, so ordinary use never " +
      "approaches it.\n\n" +
      "A wrong password and an unknown address fail identically, with the same status, body and " +
      "roughly the same timing, so this endpoint cannot be used to enumerate accounts.",
  })
  @ApiEnvelope(AccessTokenSchema, { status: 201, description: "Authenticated." })
  @ApiProblem(401, "Wrong password, unknown user, or a disabled account.", "INVALID_CREDENTIALS")
  @ApiProblem(404, "The tenant in the header does not exist or is inactive.", "TENANT_NOT_FOUND")
  @ApiCommonErrors()
  login(@Body() dto: LoginDto, @Ip() ip: string): Promise<{ accessToken: string }> {
    return this.auth.login(dto.email, dto.password, ip);
  }
}
