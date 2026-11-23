import pg from "pg";
import { migrate } from "./db/migrate.js";
import { createAuthnApi } from "./server.js";

const env = process.env;
const log = (e: Record<string, unknown>) => console.log(JSON.stringify(e));

function int(name: string, fallback: number, min: number, max: number) {
  const v = Number(env[name] ?? fallback);
  if (!Number.isInteger(v) || v < min || v > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return v;
}

function required(name: string) {
  const v = env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
}

const port = int("PORT", 8080, 1, 65535);
const poolMax = int("BAE6_AUTHN_DB_POOL_MAX", 10, 1, 100);
const shutdownDelayMs = int("BAE6_SHUTDOWN_DELAY_MS", 0, 0, 15_000);
// Capped so delay + drain + 5 s stays under the 60 s termination grace period.
const requestTimeoutMs = int("BAE6_REQUEST_TIMEOUT_MS", 30_000, 1000, 30_000);
const databaseUrl = required("BAE6_AUTHN_DATABASE_URL");

// Waiting on another replica's migration lock or building an index can exceed the request timeout.
const migrator = new pg.Client({
  connectionString: databaseUrl,
  connectionTimeoutMillis: 5000,
  statement_timeout: 300_000,
});
await migrator.connect();
try {
  log({ msg: "migrations applied", applied: await migrate(migrator) });
} finally {
  await migrator.end();
}

const pool = new pg.Pool({
  connectionString: databaseUrl,
  max: poolMax,
  connectionTimeoutMillis: 5000,
  statement_timeout: 15_000,
});
pool.on("error", (err) => log({ msg: "pool_error", error: err.name }));

const server = createAuthnApi({
  ping: async () => void (await pool.query("SELECT 1")),
  requestTimeoutMs,
  log,
});
server.listen(port, "0.0.0.0", () => log({ msg: "listening", port }));

let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  server.drain();
  setTimeout(() => {
    server.close(async () => {
      await pool.end().catch(() => {});
      process.exit(0);
    });
    server.closeIdleConnections();
    setTimeout(() => process.exit(1), requestTimeoutMs + 5000).unref();
  }, shutdownDelayMs).unref();
};
process.once("SIGTERM", stop);
process.once("SIGINT", stop);
