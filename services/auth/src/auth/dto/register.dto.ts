import { IsEmail, IsString, MinLength } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class RegisterDto {
  @ApiProperty({ format: "email", example: "user@acme.example" })
  @IsEmail()
  email!: string;

  // 12-char minimum as a sane default; tune to your password policy.
  @ApiProperty({
    format: "password",
    minLength: 12,
    example: "correct-horse-battery-staple",
    description: "At least 12 characters. Length is the only rule; see LoginDto for why.",
  })
  @IsString()
  @MinLength(12)
  password!: string;
}
