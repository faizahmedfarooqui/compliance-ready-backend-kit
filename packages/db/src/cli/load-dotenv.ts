/**
 * The `.env` loader every operator CLI in this package needs, defined once.
 *
 * Six CLIs carried a byte-identical copy of this function: the audit verifier, the contention and
 * immutability probes, the tenant-admin seed, the key manager and the token decoder. Identical today is
 * not the point; the point is that a fix to any of them would have had to be made six times, and the
 * fifth and sixth would eventually be missed. Verified byte-identical before extracting, so this is a
 * pure move with no behaviour change.
 *
 * NOT exported from the package's public index, deliberately. It is CLI plumbing, and an export invites
 * service code to import it, which is how `readPage` and `toStored` in verify-chain.ts came to be
 * un-exported on review. Anything inside the service should take configuration through
 * `@compliance-kit/config`'s `loadConfig`, which validates.
 *
 * WHY NOT REUSE `@compliance-kit/config`'s loadLocalDotenv. It is the same algorithm, and depending on
 * it would give `packages/db` a dependency on the service's configuration package purely for a
 * development-time convenience. `packages/config` owns the SERVICE's validated environment schema; these
 * CLIs read two or three variables directly and deliberately never build an AppConfig, so the coupling
 * would buy nothing and would make the config package a dependency of the seed script and every operator
 * tool. If that dependency is ever wanted for another reason, collapse the two then.
 */
import { existsSync } from "node:fs";
import path from "node:path";
import { config as readDotenvFile } from "dotenv";

/**
 * Populate `process.env` from the nearest `.env`, walking up from the working directory.
 *
 * Walks up because a CLI is run from wherever the operator happens to be while the developer's `.env`
 * lives at the repo root, so neither location alone is reliable. Skipped entirely under
 * `NODE_ENV=production`, where configuration is expected to arrive from the environment or a secrets
 * manager. dotenv never overwrites a variable that is already set, so a real environment always wins.
 */
export function loadLocalDotenv(): void {
  if (process.env.NODE_ENV === "production") return;
  let dir = process.cwd();
  for (let level = 0; level < 5; level += 1) {
    const candidate = path.join(dir, ".env");
    if (existsSync(candidate)) {
      readDotenvFile({ path: candidate, quiet: true });
      return;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return;
    dir = parent;
  }
}
