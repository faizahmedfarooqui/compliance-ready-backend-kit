/**
 * Injection tokens for the process-wide singletons.
 *
 * Deliberately in their own file with no imports. When these lived in core.module.ts, any
 * provider that needed a token had to import the module, while the module had to import the
 * provider to register it. That cycle makes the token `undefined` at the moment the `@Inject`
 * decorator is evaluated, and Nest reports it as an unresolvable dependency at index [0]
 * rather than as a circular import, which is a confusing way to spend an afternoon.
 */
export const CONFIG = Symbol("CONFIG");
export const CONNECTION_MANAGER = Symbol("CONNECTION_MANAGER");
