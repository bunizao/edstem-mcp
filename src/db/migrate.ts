import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type Database from "better-sqlite3";

const MIGRATIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "src",
  "db",
  "migrations"
);

export function migrateDatabase(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at INTEGER NOT NULL
    );
  `);

  const applied = new Set<number>(
    db.prepare("SELECT version FROM schema_migrations").all().map((row) => {
      const value = (row as { version: number }).version;
      return value;
    })
  );

  const migrations = readdirSync(MIGRATIONS_DIR)
    .filter((file) => file.endsWith(".sql"))
    .sort();

  for (const file of migrations) {
    const version = Number.parseInt(file.slice(0, 3), 10);
    if (Number.isNaN(version) || applied.has(version)) {
      continue;
    }

    const sql = readFileSync(path.join(MIGRATIONS_DIR, file), "utf-8");
    const apply = db.transaction(() => {
      db.exec(sql);
      db.prepare(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"
      ).run(version, Date.now());
    });
    apply();
  }
}
