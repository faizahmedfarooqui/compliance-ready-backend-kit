import { Injectable, Logger } from "@nestjs/common";
import { tenantClient } from "@compliance-kit/db";
import {
  EmailAlreadyRegisteredError,
  InvalidCredentialsError,
  type AccessTokenClaims,
} from "@compliance-kit/common";
import { TenantContextService } from "../tenancy/tenant-context.service";
import { PasswordService } from "./password.service";
import { TokenService } from "./token.service";
import { LoginThrottleService } from "./login-throttle.service";
import { AuditService } from "../audit/audit.service";

/** Prisma's unique-constraint violation. */
const UNIQUE_VIOLATION = "P2002";

/**
 * Email addresses are normalised to lower case on the way in and on the way out. The
 * unique index is on the raw column, so without this "Alice@example.com" and
 * "alice@example.com" would be two separate accounts in the same tenant.
 */
function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly tenantCtx: TenantContextService,
    private readonly passwords: PasswordService,
    private readonly tokens: TokenService,
    private readonly throttle: LoginThrottleService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Create an unprivileged user in the current tenant. New users hold no roles: the
   * tenant's administrator is created at provisioning time and grants access from there.
   */
  async register(email: string, password: string): Promise<{ id: string; email: string }> {
    const passwordHash = await this.passwords.hash(password);
    try {
      const created = await this.tenantCtx.db.user.create({
        data: { email: normaliseEmail(email), passwordHash },
        select: { id: true, email: true },
      });
      // `system` rather than `user`: the account did not exist when the request arrived, so nobody was
      // authenticated. Recording the new user as its own actor would imply it authorised its creation.
      await this.audit.tenantEvent({
        action: "user.registered",
        actorType: "system",
        resourceType: "user",
        resourceId: created.id,
        metadata: { email: created.email },
      });
      return created;
    } catch (err) {
      if (
        err instanceof tenantClient.Prisma.PrismaClientKnownRequestError &&
        err.code === UNIQUE_VIOLATION
      ) {
        throw new EmailAlreadyRegisteredError();
      }
      throw err;
    }
  }

  /**
   * Verify credentials and issue an access token.
   *
   * The throttle check comes FIRST, before the user lookup and before any hashing. Ordering it after
   * would mean a throttled attacker still triggered a database read and a deliberately expensive
   * Argon2id verification on every rejected request, which turns the control into the thing that pays
   * for the attack. See LoginThrottleService for what the two counters cover.
   */
  async login(email: string, password: string, ip: string): Promise<{ accessToken: string }> {
    const tenantId = this.tenantCtx.tenant.id;
    try {
      await this.throttle.assertWithinLimits(tenantId, email, ip);
    } catch (err) {
      // Recorded because a throttle trip is the signal that someone is guessing, and it is the event an
      // assessor asks for when reviewing whether brute force is detected. The email is metadata rather
      // than actorId: there may be no such account, and claiming one as the actor would assert it exists.
      await this.audit.tenantEvent({
        action: "auth.login.throttled",
        actorType: "anonymous",
        sourceIp: ip,
        metadata: { email: normaliseEmail(email) },
      });
      throw err;
    }

    const user = await this.tenantCtx.db.user.findUnique({
      where: { email: normaliseEmail(email) },
    });

    // Spend the hashing work even when there is no user, so timing does not reveal
    // which addresses are registered, then fail identically either way.
    if (user?.status !== "active") {
      await this.passwords.verifyAgainstDecoy(password);
      await this.throttle.recordFailure(tenantId, email, ip);
      /**
       * One action name for "no such user" and "disabled account", matching what the RESPONSE says.
       * A separate action per cause would put the account-enumeration answer the API refuses to give
       * into the audit log, where a wider set of people can read it.
       *
       * The reason IS worth keeping, so it goes in metadata: an assessor reviewing failures needs to
       * distinguish a disabled account being probed from an address that was never registered.
       */
      await this.audit.tenantEvent({
        action: "auth.login.failed",
        actorType: user ? "user" : "anonymous",
        actorId: user ? user.id : null,
        sourceIp: ip,
        metadata: {
          email: normaliseEmail(email),
          reason: user ? "account_not_active" : "no_such_user",
        },
      });
      throw new InvalidCredentialsError();
    }
    if (!(await this.passwords.verify(user.passwordHash, password))) {
      await this.throttle.recordFailure(tenantId, email, ip);
      await this.audit.tenantEvent({
        action: "auth.login.failed",
        actorType: "user",
        actorId: user.id,
        sourceIp: ip,
        metadata: { email: normaliseEmail(email), reason: "wrong_password" },
      });
      throw new InvalidCredentialsError();
    }

    // Only now, with the password proven, is the account's failure count cleared. Doing it any earlier
    // would let a failed attempt reset the counter it is supposed to increment.
    await this.throttle.recordSuccess(tenantId, email);

    await this.upgradeHashIfStale(user.id, user.passwordHash, password);

    const { roles, permissions } = await this.loadAuthz(user.id);
    const claims: AccessTokenClaims = {
      sub: user.id,
      tid: tenantId,
      roles,
      permissions,
    };
    const accessToken = await this.tokens.issue(claims);

    /**
     * After the token is issued, so a failure to mint is not recorded as a successful login. The roles
     * are recorded because "what could this session do" is the question an access review asks, and the
     * token that carries them is encrypted and short-lived, so this row is the only durable answer.
     */
    await this.audit.tenantEvent({
      action: "auth.login.succeeded",
      actorType: "user",
      actorId: user.id,
      resourceType: "user",
      resourceId: user.id,
      sourceIp: ip,
      metadata: { email: user.email, roles: roles.join(",") },
    });

    return { accessToken };
  }

  /**
   * Re-hash a password that was stored at a weaker work factor than the current one.
   *
   * Raising Argon2 parameters only protects credentials hashed after the change, so without
   * this a deployment that tightens its parameters keeps every existing password at the old
   * strength forever. A successful login is the only moment the plaintext is available to
   * re-hash with.
   *
   * Deliberately non-fatal: the caller has already proven their password, so a failed
   * upgrade must not deny them access. It will simply be retried on their next login.
   */
  private async upgradeHashIfStale(
    userId: string,
    storedHash: string,
    password: string,
  ): Promise<void> {
    if (!this.passwords.needsRehash(storedHash)) return;
    try {
      await this.tenantCtx.db.user.update({
        where: { id: userId },
        data: { passwordHash: await this.passwords.hash(password) },
      });
    } catch (err) {
      this.logger.warn(
        `Could not upgrade password hash for user ${userId}: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /**
   * Load the user's role names and the flattened set of permission keys they grant.
   *
   * Baked into the access token at sign time, which means a permission revoked mid-session
   * stays usable until the token expires (default 15 minutes). That is the standard
   * trade-off for stateless tokens; if your access review requires immediate revocation,
   * check permissions against the database per request or keep a revocation list.
   */
  private async loadAuthz(userId: string): Promise<{ roles: string[]; permissions: string[] }> {
    const assignments = await this.tenantCtx.db.userRole.findMany({
      where: { userId },
      select: {
        role: {
          select: {
            name: true,
            permissions: { select: { permission: { select: { key: true } } } },
          },
        },
      },
    });

    return {
      roles: assignments.map((a) => a.role.name),
      permissions: [
        ...new Set(assignments.flatMap((a) => a.role.permissions.map((p) => p.permission.key))),
      ],
    };
  }
}
