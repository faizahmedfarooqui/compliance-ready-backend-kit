import { IsString, Matches, MinLength } from "class-validator";

/**
 * Provisioning creates a tenant's database and RBAC catalogue. It deliberately takes no
 * credentials and creates no users: a tenant's first administrator is seeded as a separate,
 * explicit step (`pnpm db:seed:admin`), so that creating infrastructure and granting a
 * human administrative access stay distinct and separately auditable.
 */
export class ProvisionTenantDto {
  // Lowercase slug; becomes part of the tenant's database name (validated again downstream).
  @Matches(/^[a-z][a-z0-9-]{1,40}$/, {
    message: "slug must be lowercase, start with a letter, and use only a-z, 0-9, hyphen",
  })
  slug!: string;

  @IsString()
  @MinLength(2)
  name!: string;
}
