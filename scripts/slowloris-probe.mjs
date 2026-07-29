/**
 * Prove the request timeout actually reaches the socket.
 *
 * A unit test can assert that config says 30000. It cannot tell you whether Fastify passed the value
 * to the Node server, and that is the half that was broken: Fastify defaults `requestTimeout` to 0 and
 * assigns it unconditionally, so the default DISABLES the timeout rather than inheriting Node's 300s.
 * Setting the option and setting it effectively are different claims, and only a real socket can
 * settle the second one.
 *
 * The attack this reproduces is the one nothing else bounded. Node's `headersTimeout` (60s, which
 * Fastify leaves alone) already covers a client that dribbles its headers, so this sends COMPLETE,
 * valid headers, declares a Content-Length, and then sends the body one byte at a time. No individual
 * gap looks suspicious, no inactivity timeout fires, and before the fix the connection stayed open for
 * as long as the client cared to hold it. Multiply by the connection limit and the server is out of
 * sockets while every health check still passes.
 *
 * Usage:
 *   node scripts/slowloris-probe.mjs [--host localhost] [--port 3011] [--timeout-ms 30000]
 *
 * Exits 0 only if the server answered 408 at roughly the configured timeout. See `finish`: any other
 * status, an instant 408, a silent close, or a connection held past the deadline all exit 1.
 */
import net from "node:net";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1]) return process.argv[i + 1];
  return fallback;
}

const host = arg("host", "localhost");
const port = Number(arg("port", process.env.PORT ?? "3011"));
// Read from the environment so CI can point this at a deliberately short timeout and stay fast,
// while the 30s production default is asserted by the config unit tests instead.
const timeoutMs = Number(arg("timeout-ms", process.env.REQUEST_TIMEOUT_MS ?? "30000"));

// Enough slack for scheduling and TLS-free connect on a loaded CI runner, not enough to mask a
// timeout that is off by an order of magnitude.
const grace = 5_000;
const deadline = timeoutMs + grace;

const started = Date.now();
const socket = net.connect({ host, port });
let closed = false;
let dribbles = 0;

socket.on("connect", () => {
  // Complete, well-formed headers. The server has everything it needs to route the request and is
  // now waiting on a body that will never arrive in full.
  socket.write(
    "POST /api/auth/login HTTP/1.1\r\n" +
      `Host: ${host}:${port}\r\n` +
      "Content-Type: application/json\r\n" +
      "Content-Length: 4096\r\n" +
      "\r\n",
  );

  // One byte every two seconds, forever. Valid JSON so far, just never finished.
  socket.write("{");
  const dribble = setInterval(() => {
    if (closed) {
      clearInterval(dribble);
      return;
    }
    dribbles += 1;
    socket.write(" ");
  }, 2_000);
  dribble.unref?.();
});

/**
 * Decide the outcome.
 *
 * Two conditions, and both are needed. Requiring only that the connection closed in time would let this
 * pass on ANY response: a 400 from a body-limit rejection, a 401 from a guard, a 413, anything that
 * happens to arrive quickly. The probe would report success while proving nothing whatever about
 * requestTimeout, which is the one thing it exists to prove.
 *
 *  1. The status must be 408. That is what Node sends when the request timeout expires, and nothing
 *     else in this service sends it.
 *  2. It must have taken roughly the timeout to arrive. An instant 408 would mean something other than
 *     the timeout produced it, so a small tolerance below the configured value, and no more.
 *
 * A closed connection with no response at all is not a pass either. Node answers a request timeout with
 * 408 before hanging up, so a silent close is some other failure wearing the same shape.
 */
function finish(reason, status) {
  if (closed) return;
  closed = true;
  const elapsed = Date.now() - started;
  socket.destroy();

  const tooLate = elapsed > deadline;
  // Allowance for measurement jitter only. Node fires at or after the deadline, never meaningfully
  // before it.
  const tooEarly = elapsed < timeoutMs - 500;

  if (status !== 408) {
    process.stderr.write(
      `FAIL  expected 408 Request Timeout, got ${status ?? "no response"} after ${elapsed}ms ` +
        `(${reason}). A response that is not a 408 means something other than requestTimeout ended ` +
        `this request, so the timeout is not proven to be in effect.\n`,
    );
    process.exit(1);
  }
  if (tooEarly) {
    process.stderr.write(
      `FAIL  got a 408 after only ${elapsed}ms, well inside the ${timeoutMs}ms timeout. Something ` +
        `other than the request timeout produced it.\n`,
    );
    process.exit(1);
  }
  if (tooLate) {
    process.stderr.write(
      `FAIL  server held the connection for ${elapsed}ms, longer than ${deadline}ms (${reason}).\n`,
    );
    process.exit(1);
  }

  process.stdout.write(
    `PASS  server answered 408 after ${elapsed}ms, at or just past the ${timeoutMs}ms request ` +
      `timeout and within the ${grace}ms grace. Sent ${dribbles} dribbled byte(s).\n`,
  );
  process.exit(0);
}

// A close or a FIN with no status line seen is a failure: Node sends 408 before hanging up on a
// request timeout, so a silent close is a different fault that happens to look similar.
socket.on("close", () => finish("socket closed with no response", undefined));
socket.on("end", () => finish("server sent FIN with no response", undefined));
socket.on("data", (chunk) => {
  const head = chunk.toString("latin1").split("\r\n")[0];
  const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1]);
  finish(`server responded: ${head}`, Number.isNaN(status) ? undefined : status);
});

socket.on("error", (err) => {
  // ECONNRESET is the server hanging up, not a probe failure.
  if (err.code === "ECONNRESET") return finish("connection reset by server", undefined);
  process.stderr.write(`FAIL  probe could not run: ${err.message}\n`);
  process.exit(1);
});

// Backstop, in case the socket neither closes nor errors.
setTimeout(() => {
  process.stderr.write(
    `FAIL  server still holding the connection after ${deadline}ms with ${dribbles} dribbled ` +
      `byte(s). requestTimeout is not in effect.\n`,
  );
  process.exit(1);
}, deadline + 1_000).unref();
