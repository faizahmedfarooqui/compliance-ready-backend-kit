import { SetMetadata } from "@nestjs/common";

export const RAW_RESPONSE_KEY = "raw_response";

/**
 * Exempt a route from the `{ success, data, meta }` envelope.
 *
 * For routes whose body is defined by someone else's standard. The envelope is right for this kit's
 * own API, and wrong the moment a response has to satisfy an external specification: a JWKS
 * document is `{ "keys": [...] }` at the top level per RFC 7517, so wrapping it produces something
 * no standard client can read. jose's own `createRemoteJWKSet` would reject it, and the
 * `application/jwk-set+json` content type would be a false claim about the body.
 *
 * This was found by actually fetching the endpoint and reading the bytes, which is the only way to
 * catch it: every layer in isolation looked correct.
 *
 * Use sparingly. Every exemption is one more shape a client has to know about, so the bar is "an
 * external specification dictates this body", not "the envelope is inconvenient here".
 */
export const RawResponse = () => SetMetadata(RAW_RESPONSE_KEY, true);
