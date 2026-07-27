import { describe, expect, it } from "vitest";
import type { ValidationError } from "class-validator";
import { ValidationFailedError } from "@compliance-kit/common";
import { validationExceptionFactory } from "./validation-exception.factory";

/**
 * Minimal ValidationError. No cast is needed: every other field on class-validator's
 * ValidationError is optional, so this object literal already satisfies the type.
 */
function error(
  property: string,
  constraints?: Record<string, string>,
  children?: ValidationError[],
): ValidationError {
  return { property, constraints, children };
}

describe("validationExceptionFactory", () => {
  it("returns a ValidationFailedError, so the problem-details filter renders it", () => {
    const result = validationExceptionFactory([
      error("slug", { matches: "slug must be lowercase" }),
    ]);
    expect(result).toBeInstanceOf(ValidationFailedError);
    expect(result.code).toBe("VALIDATION_FAILED");
  });

  it("emits one entry per failed constraint with a JSON Pointer", () => {
    const result = validationExceptionFactory([
      error("slug", { matches: "slug must be lowercase" }),
      error("name", { minLength: "name is too short" }),
    ]);
    expect(result.errors).toEqual([
      { detail: "slug must be lowercase", pointer: "#/slug" },
      { detail: "name is too short", pointer: "#/name" },
    ]);
  });

  it("reports every constraint on a single field, not just the first", () => {
    const result = validationExceptionFactory([
      error("password", { minLength: "too short", isString: "must be a string" }),
    ]);
    expect(result.errors).toHaveLength(2);
    expect(result.errors.map((e) => e.pointer)).toEqual(["#/password", "#/password"]);
  });

  // Reporting only the parent property would lose which inner field was actually wrong.
  it("recurses into nested DTOs and points at the inner field", () => {
    const result = validationExceptionFactory([
      error("admin", undefined, [error("email", { isEmail: "must be an email" })]),
    ]);
    expect(result.errors).toEqual([{ detail: "must be an email", pointer: "#/admin/email" }]);
  });

  it("handles array members, which arrive as numerically-named children", () => {
    const result = validationExceptionFactory([
      error("items", undefined, [
        error("0", undefined, [error("id", { isUuid: "must be a uuid" })]),
      ]),
    ]);
    expect(result.errors).toEqual([{ detail: "must be a uuid", pointer: "#/items/0/id" }]);
  });

  // RFC 6901: `~` and `/` must be escaped, and in that order, or a name containing a slash reads
  // as two path segments.
  it("escapes ~ and / in property names per RFC 6901", () => {
    const result = validationExceptionFactory([
      error("odd/name", { isString: "bad" }),
      error("tilde~name", { isString: "bad" }),
    ]);
    expect(result.errors.map((e) => e.pointer)).toEqual(["#/odd~1name", "#/tilde~0name"]);
  });

  it("escapes ~ before /, so a name with both is unambiguous", () => {
    const result = validationExceptionFactory([error("a~/b", { isString: "bad" })]);
    // "a~/b" -> escape ~ first ("a~0/b") -> then / ("a~0~1b"). The reverse order would produce
    // "a~0~01b", which decodes back to the wrong name.
    expect(result.errors[0].pointer).toBe("#/a~0~1b");
  });

  it("produces no entries for a field with no constraints and no children", () => {
    const result = validationExceptionFactory([error("mystery")]);
    expect(result.errors).toEqual([]);
  });

  it("keeps the title stable and puts nothing request-specific in it (RFC 9457 s3.1.3)", () => {
    const a = validationExceptionFactory([error("slug", { matches: "x" })]);
    const b = validationExceptionFactory([error("name", { minLength: "y" })]);
    expect(a.title).toBe(b.title);
    expect(a.title).not.toContain("slug");
  });
});
