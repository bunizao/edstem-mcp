import type Database from "better-sqlite3";

export interface UserRecord {
  createdAt: number;
  displayName: string | null;
  email: string;
  id: number;
  lastLoginAt: number | null;
  passwordHash: string;
}

type UserRow = {
  created_at: number;
  display_name: string | null;
  email: string;
  id: number;
  last_login_at: number | null;
  password_hash: string;
};

export class UsersRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  create(input: {
    createdAt: number;
    displayName?: string;
    email: string;
    passwordHash: string;
  }): UserRecord {
    const result = this.db
      .prepare(
        `
          INSERT INTO users (email, password_hash, display_name, created_at)
          VALUES (@email, @passwordHash, @displayName, @createdAt)
        `
      )
      .run({
        createdAt: input.createdAt,
        displayName: input.displayName ?? null,
        email: input.email,
        passwordHash: input.passwordHash
      });

    return this.getById(Number(result.lastInsertRowid)) as UserRecord;
  }

  delete(userId: number): void {
    this.db.prepare("DELETE FROM users WHERE id = ?").run(userId);
  }

  getByEmail(email: string): UserRecord | null {
    const row = this.db
      .prepare(
        `
          SELECT id, email, password_hash, display_name, created_at, last_login_at
          FROM users
          WHERE email = ?
        `
      )
      .get(email) as UserRow | undefined;

    return row ? mapUser(row) : null;
  }

  getById(userId: number): UserRecord | null {
    const row = this.db
      .prepare(
        `
          SELECT id, email, password_hash, display_name, created_at, last_login_at
          FROM users
          WHERE id = ?
        `
      )
      .get(userId) as UserRow | undefined;

    return row ? mapUser(row) : null;
  }

  setPasswordHash(userId: number, passwordHash: string): void {
    this.db
      .prepare("UPDATE users SET password_hash = ? WHERE id = ?")
      .run(passwordHash, userId);
  }

  touchLastLogin(userId: number, timestamp: number): void {
    this.db
      .prepare("UPDATE users SET last_login_at = ? WHERE id = ?")
      .run(timestamp, userId);
  }
}

function mapUser(row: UserRow): UserRecord {
  return {
    createdAt: row.created_at,
    displayName: row.display_name,
    email: row.email,
    id: row.id,
    lastLoginAt: row.last_login_at,
    passwordHash: row.password_hash
  };
}
