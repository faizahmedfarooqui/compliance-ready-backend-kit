import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PACKAGE_INFO, readPackageInfo } from "./package-info";

const packageJson = JSON.parse(
  readFileSync(path.resolve(__dirname, "..", "..", "package.json"), "utf8"),
) as { name: string; version: string };

describe("readPackageInfo", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  /**
   * The bug this replaced: the OpenAPI document took npm_package_version, which a package-manager
   * script sets and `node dist/main.js` (the container) does not, and otherwise said "0.1.0". The
   * smoke suite cannot catch that on its own, because CI starts the service through pnpm, which sets
   * the variable. So this sets it to a lie and requires the file's answer regardless.
   */
  it("reads the version from package.json, whatever npm_package_version says", () => {
    vi.stubEnv("npm_package_version", "9.9.9-not-this");
    expect(readPackageInfo()).toEqual({ name: packageJson.name, version: packageJson.version });
  });

  it("reads it even when nothing set npm_package_version, as in the container", () => {
    vi.stubEnv("npm_package_version", undefined);
    expect(readPackageInfo().version).toBe(packageJson.version);
  });

  it("is what PACKAGE_INFO holds", () => {
    expect(PACKAGE_INFO).toEqual({ name: packageJson.name, version: packageJson.version });
  });
});
