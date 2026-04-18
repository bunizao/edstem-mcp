import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export interface AuthorizationCodeRecord {
  clientId: string;
  codeChallenge: string;
  displayName: string;
  expiresAt: number;
  issuedAt: number;
  redirectUri: string;
  resource?: string;
  scopes: string[];
  userId: string;
  username: string;
}

export interface AccessTokenRecord {
  clientId: string;
  displayName: string;
  expiresAt: number;
  issuedAt: number;
  refreshToken?: string;
  resource?: string;
  scopes: string[];
  userId: string;
  username: string;
}

export interface RefreshTokenRecord {
  clientId: string;
  displayName: string;
  expiresAt: number;
  issuedAt: number;
  resource?: string;
  scopes: string[];
  userId: string;
  username: string;
}

interface PersistedOAuthState {
  accessTokens: Record<string, AccessTokenRecord>;
  authorizationCodes: Record<string, AuthorizationCodeRecord>;
  clients: Record<string, OAuthClientInformationFull>;
  refreshTokens: Record<string, RefreshTokenRecord>;
}

const EMPTY_STATE: PersistedOAuthState = {
  accessTokens: {},
  authorizationCodes: {},
  clients: {},
  refreshTokens: {}
};

export class FileOAuthStore {
  private cache: PersistedOAuthState | null = null;
  private readonly filePath: string;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
  }

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const state = await this.load();
    return state.clients[clientId];
  }

  async saveClient(client: OAuthClientInformationFull): Promise<void> {
    await this.update((state) => {
      state.clients[client.client_id] = client;
    });
  }

  async getAuthorizationCode(code: string): Promise<AuthorizationCodeRecord | undefined> {
    const state = await this.load();
    return state.authorizationCodes[code];
  }

  async saveAuthorizationCode(code: string, record: AuthorizationCodeRecord): Promise<void> {
    await this.update((state) => {
      state.authorizationCodes[code] = record;
    });
  }

  async deleteAuthorizationCode(code: string): Promise<void> {
    await this.update((state) => {
      delete state.authorizationCodes[code];
    });
  }

  async getAccessToken(token: string): Promise<AccessTokenRecord | undefined> {
    const state = await this.load();
    return state.accessTokens[token];
  }

  async saveAccessToken(token: string, record: AccessTokenRecord): Promise<void> {
    await this.update((state) => {
      state.accessTokens[token] = record;
    });
  }

  async deleteAccessToken(token: string): Promise<void> {
    await this.update((state) => {
      delete state.accessTokens[token];
    });
  }

  async getRefreshToken(token: string): Promise<RefreshTokenRecord | undefined> {
    const state = await this.load();
    return state.refreshTokens[token];
  }

  async saveRefreshToken(token: string, record: RefreshTokenRecord): Promise<void> {
    await this.update((state) => {
      state.refreshTokens[token] = record;
    });
  }

  async deleteRefreshToken(token: string): Promise<void> {
    await this.update((state) => {
      delete state.refreshTokens[token];
    });
  }

  async pruneExpired(now: number = Date.now()): Promise<void> {
    await this.update((state) => {
      for (const [token, record] of Object.entries(state.accessTokens)) {
        if (record.expiresAt <= now) {
          delete state.accessTokens[token];
        }
      }
      for (const [token, record] of Object.entries(state.refreshTokens)) {
        if (record.expiresAt <= now) {
          delete state.refreshTokens[token];
        }
      }
      for (const [code, record] of Object.entries(state.authorizationCodes)) {
        if (record.expiresAt <= now) {
          delete state.authorizationCodes[code];
        }
      }
    });
  }

  private async load(): Promise<PersistedOAuthState> {
    if (this.cache) {
      return this.cache;
    }

    try {
      const raw = await readFile(this.filePath, "utf-8");
      const parsed = JSON.parse(raw) as Partial<PersistedOAuthState>;
      this.cache = {
        accessTokens: parsed.accessTokens ?? {},
        authorizationCodes: parsed.authorizationCodes ?? {},
        clients: parsed.clients ?? {},
        refreshTokens: parsed.refreshTokens ?? {}
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      this.cache = structuredClone(EMPTY_STATE);
    }

    return this.cache;
  }

  private async update(mutator: (state: PersistedOAuthState) => void): Promise<void> {
    const run = async () => {
      const state = await this.load();
      mutator(state);
      await this.persist(state);
    };

    this.writeQueue = this.writeQueue.then(run, run);
    await this.writeQueue;
  }

  private async persist(state: PersistedOAuthState): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const tempFile = `${this.filePath}.tmp`;
    await writeFile(tempFile, JSON.stringify(state, null, 2), "utf-8");
    await rename(tempFile, this.filePath);
  }
}
