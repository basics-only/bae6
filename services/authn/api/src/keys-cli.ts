import pg from "pg";
import { KeyError, unretireKey } from "./keys.js";

const [command, kid] = process.argv.slice(2);
const databaseUrl = process.env.BAE6_AUTHN_DATABASE_URL;
if (command !== "unretire" || !kid || !/^[A-Za-z0-9_-]{43}$/.test(kid)) {
  console.error("usage: node dist/keys-cli.js unretire <kid>");
  process.exit(2);
}
if (!databaseUrl) {
  console.error("BAE6_AUTHN_DATABASE_URL is required");
  process.exit(2);
}

const pool = new pg.Pool({
  connectionString: databaseUrl,
  max: 1,
  connectionTimeoutMillis: 5000,
  statement_timeout: 15_000,
});
try {
  await unretireKey(pool, kid);
  console.log(
    `key ${kid} is next again; replicas with it as BAE6_AUTHN_ACTIVE_SIGNING_KEY promote it after the promotion delay`,
  );
} catch (err) {
  if (!(err instanceof KeyError)) throw err;
  console.error(err.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
