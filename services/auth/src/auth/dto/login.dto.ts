import { IsEmail, IsString } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class LoginDto {
  @ApiProperty({ format: "email", example: "admin@acme.example" })
  @IsEmail()
  email!: string;

  @ApiProperty({
    format: "password",
    example: "correct-horse-battery-staple",
    description:
      "No maximum length and no character-class rules, deliberately. Argon2id hashes any input to a " +
      "fixed size, and composition rules push people towards predictable substitutions.",
  })
  @IsString()
  password!: string;
}
