import type { ValidationError } from "class-validator";
import { ValidationFailedError, type FieldProblem } from "@compliance-kit/common";

/**
 * Translate class-validator failures into our own domain error, so that ValidationPipe stops
 * throwing a Nest BadRequestException with its own body shape and every error on the wire is
 * rendered by ProblemDetailsFilter instead.
 *
 * Field locations are emitted as JSON Pointers (RFC 6901), matching the `errors` extension in
 * the RFC 9457 validation illustration (§3.2): `{ detail, pointer }`.
 */
export function validationExceptionFactory(errors: ValidationError[]): ValidationFailedError {
  return new ValidationFailedError(flatten(errors));
}

function flatten(errors: ValidationError[], path: string[] = []): FieldProblem[] {
  const problems: FieldProblem[] = [];

  for (const error of errors) {
    const here = [...path, error.property];

    for (const detail of Object.values(error.constraints ?? {})) {
      problems.push({ detail, pointer: pointerFor(here) });
    }

    // Nested DTOs and array members arrive as children, so recurse rather than reporting the
    // parent property alone and losing which inner field was wrong.
    if (error.children && error.children.length > 0) {
      problems.push(...flatten(error.children, here));
    }
  }

  return problems;
}

/**
 * RFC 6901 JSON Pointer. `~` and `/` inside a property name have to be escaped as `~0` and
 * `~1`, in that order, or a name containing a slash would silently read as two segments.
 */
function pointerFor(segments: string[]): string {
  const escaped = segments.map((s) => s.replaceAll("~", "~0").replaceAll("/", "~1"));
  return `#/${escaped.join("/")}`;
}
