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
  ) {}

  /**
   * Create an unprivileged user in the current tenant. New users hold no roles: the
   * tenant's administrator is created at provisioning time and grants access from there.
   */
  async register(email: string, password: string): Promise<{ id: string; email: string }> {
    const passwordHash = await this.passwords.hash(password);
    try {
      return await this.tenantCtx.db.user.create({
        data: { email: normaliseEmail(email), passwordHash },
        select: { id: true, email: true },
      });
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

  async login(email: string, password: string): Promise<{ accessToken: string }> {
    const user = await this.tenantCtx.db.user.findUnique({
      where: { email: normaliseEmail(email) },
    });

    // Spend the hashing work even when there is no user, so timing does not reveal
    // which addresses are registered, then fail identically either way.
    if (!user || user.status !== "active") {
      await this.passwords.verifyAgainstDecoy(password);
      throw new InvalidCredentialsError();
    }
    if (!(await this.passwords.verify(user.passwordHash, password))) {
      throw new InvalidCredentialsError();
    }

    await this.upgradeHashIfStale(user.id, user.passwordHash, password);

    const { roles, permissions } = await this.loadAuthz(user.id);
    const claims: AccessTokenClaims = {
      sub: user.id,
      tid: this.tenantCtx.tenant.id,
      roles,
      permissions,
    };
    return { accessToken: await this.tokens.issue(claims) };
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
