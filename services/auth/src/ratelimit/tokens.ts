/**
 * Injection token for the shared Redis connection.
 *
 * In its own import-free file for the same reason as core/tokens.ts: a token defined in the module
 * that registers it creates a cycle with any provider that needs it, and Nest surfaces that as an
 * unresolvable dependency at some index rather than as a circular import.
 */
export const REDIS = Symbol("REDIS");
