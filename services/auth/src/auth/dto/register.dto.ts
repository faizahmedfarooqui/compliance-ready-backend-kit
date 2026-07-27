import { IsEmail, IsString, MinLength } from "class-validator";

export class RegisterDto {
  @IsEmail()
  email!: string;

  // 12-char minimum as a sane default; tune to your password policy.
  @IsString()
  @MinLength(12)
  password!: string;
}
