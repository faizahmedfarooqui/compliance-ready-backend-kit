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
 * Exits 0 if the server hung up within the timeout (plus grace), 1 if it did not.
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

function finish(reason) {
  if (closed) return;
  closed = true;
  const elapsed = Date.now() - started;
  socket.destroy();

  if (elapsed <= deadline) {
    process.stdout.write(
      `PASS  server closed the connection after ${elapsed}ms (${reason}), ` +
        `within the ${timeoutMs}ms request timeout plus ${grace}ms grace. ` +
        `Sent ${dribbles} dribbled byte(s).\n`,
    );
    process.exit(0);
  }

  process.stderr.write(
    `FAIL  server held the connection for ${elapsed}ms, longer than ${deadline}ms (${reason}).\n`,
  );
  process.exit(1);
}

// Any of these means the server gave up on us, which is the desired behaviour. Fastify answers a
// request timeout with 408 before closing, so a readable response is a pass too.
socket.on("close", () => finish("socket closed"));
socket.on("end", () => finish("server sent FIN"));
socket.on("data", (chunk) => {
  const head = chunk.toString("latin1").split("\r\n")[0];
  finish(`server responded: ${head}`);
});

socket.on("error", (err) => {
  // ECONNRESET is the server hanging up, not a probe failure.
  if (err.code === "ECONNRESET") return finish("connection reset by server");
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
