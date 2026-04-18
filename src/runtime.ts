import type Database from "better-sqlite3";
import pino, { type Logger } from "pino";

import type { AppConfig } from "./config.js";
import { openDatabase } from "./db/connection.js";
import { migrateDatabase } from "./db/migrate.js";
import { CredentialsRepository } from "./credentials/repository.js";
import { CredentialsService } from "./credentials/service.js";
import { SqlOAuthStore } from "./oauth/sql-store.js";
import { EdstemOAuthProvider } from "./oauth/provider.js";
import { UsersRepository } from "./users/repository.js";
import { UsersService } from "./users/service.js";

export interface Runtime {
  close(): void;
  config: AppConfig;
  credentials: CredentialsService;
  db: Database.Database;
  logger: Logger;
  oauthProvider: EdstemOAuthProvider;
  store: SqlOAuthStore;
  users: UsersService;
}

export function createRuntime(config: AppConfig, logger?: Logger): Runtime {
  const db = openDatabase(config.databasePath);
  migrateDatabase(db);

  const resolvedLogger = logger ?? pino({ level: config.logLevel });
  const users = new UsersService(new UsersRepository(db));
  const credentials = new CredentialsService(new CredentialsRepository(db), config);
  const store = new SqlOAuthStore(db);
  const oauthProvider = new EdstemOAuthProvider({
    config,
    credentials,
    store,
    users
  });

  return {
    close() {
      db.close();
    },
    config,
    credentials,
    db,
    logger: resolvedLogger,
    oauthProvider,
    store,
    users
  };
}
