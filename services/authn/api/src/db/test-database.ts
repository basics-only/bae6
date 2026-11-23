import { randomUUID } from "node:crypto";
import pg from "pg";
import { migrate } from "./migrate.js";

export async function migratedTestDatabase(url: string, prefix: string) {
  const name = `${prefix}_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  const target = new URL(url);
  target.pathname = `/${name}`;
  const pool = new pg.Pool({ connectionString: target.toString(), max: 8 });

  const close = async () => {
    try {
      await pool.end();
      for (let attempt = 0; ; attempt++) {
        const { rows } = await admin.query(
          "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1",
          [name],
        );
        if (rows[0].n === 0) break;
        if (attempt === 100)
          throw new Error(`connections to ${name} still open after pool.end()`);
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      await admin.query(`DROP DATABASE IF EXISTS ${name}`);
    } finally {
      await admin.end();
    }
  };

  try {
    const client = await pool.connect();
    try {
      await migrate(client);
    } finally {
      client.release();
    }
  } catch (err) {
    await close();
    throw err;
  }
  return { pool, close };
}
