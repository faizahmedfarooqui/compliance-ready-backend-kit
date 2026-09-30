import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * This service's own name and version, read from its package.json once at module load.
 *
 * One source for both places the version is published, /api/health and the OpenAPI document, because
 * the two used to disagree. The OpenAPI document took `process.env.npm_package_version`, which only a
 * package-manager script sets, and fell back to a hardcoded "0.1.0". The container starts the service
 * as `node dist/main.js`, so in production the published API contract named a version two releases
 * old while /api/health, which read the file, said 0.2.0.
 *
 * Resolves from both `dist/common/` and `src/common/`, since `../..` from either is the service root,
 * and from the image, where `pnpm deploy` puts package.json at the root beside `dist/`.
 */
export const PACKAGE_INFO: { readonly name: string; readonly version: string } = readPackageInfo();

/** Exported for its test; everything else should use PACKAGE_INFO, which reads once. */
export function readPackageInfo(): { name: string; version: string } {
  try {
    const raw = readFileSync(path.resolve(__dirname, "..", "..", "package.json"), "utf8");
    const parsed = JSON.parse(raw) as { name?: string; version?: string };
    return { name: parsed.name ?? "unknown", version: parsed.version ?? "unknown" };
  } catch {
    // Never let reporting a version be the reason a service fails to boot.
    return { name: "unknown", version: "unknown" };
  }
}
