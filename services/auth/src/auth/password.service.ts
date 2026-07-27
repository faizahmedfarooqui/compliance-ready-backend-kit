import { Injectable } from "@nestjs/common";
import {
  hashPassword,
  needsRehash,
  verifyAgainstDecoy,
  verifyPassword,
} from "@compliance-kit/crypto";

/**
 * Nest-injectable wrapper over @compliance-kit/crypto.
 *
 * The Argon2id parameters themselves live in that package, not here, because the tenant
 * admin seed script needs the same ones and two copies would eventually disagree. This
 * class exists only so services can take password hashing as an injected dependency.
 */
@Injectable()
export class PasswordService {
  hash(plaintext: string): Promise<string> {
    return hashPassword(plaintext);
  }

  verify(storedHash: string, plaintext: string): Promise<boolean> {
    return verifyPassword(storedHash, plaintext);
  }

  /** True when a stored hash was produced with weaker parameters than the current ones. */
  needsRehash(storedHash: string): boolean {
    return needsRehash(storedHash);
  }

  /**
   * Burn comparable CPU when there is no stored hash to check, so that "no such user" and
   * "wrong password" are not distinguishable by response time.
   */
  verifyAgainstDecoy(plaintext: string): Promise<false> {
    return verifyAgainstDecoy(plaintext);
  }
}
