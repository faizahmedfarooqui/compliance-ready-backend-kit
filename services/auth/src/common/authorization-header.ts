/** The parts of a request this reads, so a guard can pass its own request type straight in. */
export interface AuthorizationHeaderSource {
  headers: Record<string, string | string[] | undefined>;
  /** The Node request underneath Fastify's, which still holds every header line as sent. */
  raw?: { rawHeaders?: readonly string[] };
}

/**
 * The request's Authorization header, or undefined when it is absent or was sent more than once.
 *
 * A repeated Authorization header does NOT arrive as an array. Node keeps the first value and
 * discards the rest (`message.headers` in the Node documentation lists `authorization` among the
 * duplicates it drops), so `headers.authorization` is a plain string even when a client sent two.
 * Checked on Node 24 rather than assumed: two `Authorization` lines give the string of the first,
 * while `rawHeaders` lists both. Both guards used to assume the array form and refuse it, so that
 * refusal could never run, and a request carrying two credentials was judged on whichever came
 * first. Behind a proxy that reads the last one instead, the same bytes would authenticate as two
 * different principals depending on who was asking.
 *
 * So the raw header list is counted, and more than one Authorization line is treated the same as
 * none: the caller gets the ordinary 401 for a missing credential, because which of two credentials
 * was meant is not something to guess.
 *
 * When there is no raw request to consult (a unit test's hand-built request), this falls back to the
 * parsed header alone, which is the most the caller has given it to go on.
 */
export function singleAuthorizationHeader(req: AuthorizationHeaderSource): string | undefined {
  const raw = req.raw?.rawHeaders;
  if (raw) {
    let seen = 0;
    // rawHeaders alternates name, value, name, value, with names exactly as the client sent them.
    for (let i = 0; i < raw.length; i += 2) {
      if (raw[i].toLowerCase() === "authorization") seen += 1;
    }
    if (seen > 1) return undefined;
  }
  const header = req.headers.authorization;
  return typeof header === "string" ? header : undefined;
}
