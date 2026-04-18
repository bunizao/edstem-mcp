import bcrypt from "bcryptjs";

import { UsersRepository, type UserRecord } from "./repository.js";

const MIN_PASSWORD_LENGTH = 10;
const BCRYPT_ROUNDS = 12;

export class DuplicateEmailError extends Error {
  constructor() {
    super("An account with that email already exists.");
    this.name = "DuplicateEmailError";
  }
}

export class InvalidCredentialsError extends Error {
  constructor() {
    super("Invalid email or password.");
    this.name = "InvalidCredentialsError";
  }
}

export class PasswordPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PasswordPolicyError";
  }
}

export class UsersService {
  private readonly repository: UsersRepository;

  constructor(repository: UsersRepository) {
    this.repository = repository;
  }

  async authenticate(email: string, password: string): Promise<UserRecord> {
    const normalizedEmail = normalizeEmail(email);
    const user = this.repository.getByEmail(normalizedEmail);
    if (!user) {
      throw new InvalidCredentialsError();
    }

    const matches = await bcrypt.compare(password, user.passwordHash);
    if (!matches) {
      throw new InvalidCredentialsError();
    }

    this.repository.touchLastLogin(user.id, Date.now());
    return this.getById(user.id);
  }

  findByEmail(email: string): UserRecord | null {
    return this.repository.getByEmail(normalizeEmail(email));
  }

  getById(userId: number): UserRecord {
    const user = this.repository.getById(userId);
    if (!user) {
      throw new Error(`User ${userId} not found`);
    }
    return user;
  }

  async register(input: {
    displayName?: string;
    email: string;
    password: string;
  }): Promise<UserRecord> {
    const email = normalizeEmail(input.email);
    validatePassword(input.password);

    if (this.repository.getByEmail(email)) {
      throw new DuplicateEmailError();
    }

    const passwordHash = await bcrypt.hash(input.password, BCRYPT_ROUNDS);
    return this.repository.create({
      createdAt: Date.now(),
      displayName: normalizeDisplayName(input.displayName),
      email,
      passwordHash
    });
  }

  async resetPassword(userId: number, password: string): Promise<void> {
    validatePassword(password);
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    this.repository.setPasswordHash(userId, passwordHash);
  }

  deleteAccount(userId: number): void {
    this.repository.delete(userId);
  }
}

function normalizeDisplayName(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function validatePassword(password: string): void {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new PasswordPolicyError(
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`
    );
  }
}
