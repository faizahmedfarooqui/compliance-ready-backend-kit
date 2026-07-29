import { IsString, Matches, MinLength } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

/**
 * Provisioning creates a tenant's database and RBAC catalogue. It deliberately takes no
 * credentials and creates no users: a tenant's first administrator is seeded as a separate,
 * explicit step (`pnpm db:seed:admin`), so that creating infrastructure and granting a
 * human administrative access stay distinct and separately auditable.
 */
export class ProvisionTenantDto {
  @ApiProperty({
    pattern: "^[a-z][a-z0-9-]{1,40}$",
    example: "acme",
    description:
      "Becomes part of the tenant's database name, which is why the pattern is this strict and is " +
      "validated again downstream: a slug reaches an identifier position in DDL.",
  })
  // Lowercase slug; becomes part of the tenant's database name (validated again downstream).
  @Matches(/^[a-z][a-z0-9-]{1,40}$/, {
    message: "slug must be lowercase, start with a letter, and use only a-z, 0-9, hyphen",
  })
  slug!: string;

  @ApiProperty({ minLength: 2, example: "Acme Corporation", description: "Display name." })
  @IsString()
  @MinLength(2)
  name!: string;
}
