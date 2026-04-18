import { randomBytes, randomUUID } from "node:crypto";

import type { Response } from "express";

import { checkResourceAllowed, resourceUrlFromServerUrl } from "@modelcontextprotocol/sdk/shared/auth-utils.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { AccessDeniedError, InvalidGrantError, InvalidScopeError, InvalidTargetError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

import type { OAuthConfig } from "../config.js";
import { renderLoginPage } from "./login-page.js";
import {
  buildExpiredSessionCookie,
  buildSessionCookie,
  createSessionForUser,
  readSessionFromCookieHeader
} from "./session.js";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  RefreshTokenRecord
} from "./store.js";
import { FileOAuthStore } from "./store.js";

const AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000;

export class FileOAuthClientsStore implements OAuthRegisteredClientsStore {
  private readonly store: FileOAuthStore;

  constructor(store: FileOAuthStore) {
    this.store = store;
  }

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.store.getClient(clientId);
  }

  async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
    await this.store.saveClient(client);
    return client;
  }
}

export class EdstemOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: OAuthRegisteredClientsStore;
  private readonly config: OAuthConfig;
  private readonly resourceUrl: URL;
  private readonly store: FileOAuthStore;

  constructor(config: OAuthConfig) {
    this.config = config;
    this.resourceUrl = resourceUrlFromServerUrl(config.mcpServerUrl);
    this.store = new FileOAuthStore(config.storePath);
    this.clientsStore = new FileOAuthClientsStore(this.store);
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const request = res.req;
    const session = readSessionFromCookieHeader(request.headers.cookie, this.config);

    if (session) {
      await this.finishAuthorization(client, params, session, res);
      return;
    }

    res.setHeader("Set-Cookie", buildExpiredSessionCookie(this.config));

    if (request.method === "POST") {
      const username = getFormField(request.body?.username);
      const password = getFormField(request.body?.password);

      if (
        username === this.config.user.username &&
        password === this.config.user.password
      ) {
        const nextSession = createSessionForUser(
          this.config.user,
          this.config.sessionTtlSeconds
        );
        res.appendHeader("Set-Cookie", buildSessionCookie(nextSession, this.config));
        await this.finishAuthorization(client, params, nextSession, res);
        return;
      }

      res
        .status(401)
        .type("html")
        .send(
          renderLoginPage({
            client,
            errorMessage: "Invalid credentials.",
            params,
            username
          })
        );
      return;
    }

    res
      .status(200)
      .type("html")
      .send(
        renderLoginPage({
          client,
          params
        })
      );
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = await this.store.getAuthorizationCode(authorizationCode);
    if (!record || record.clientId !== client.client_id || record.expiresAt <= Date.now()) {
      throw new InvalidGrantError("Invalid authorization code");
    }
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.store.getAuthorizationCode(authorizationCode);
    if (!record) {
      throw new InvalidGrantError("Invalid authorization code");
    }
    if (record.clientId !== client.client_id) {
      throw new InvalidGrantError("Authorization code was issued to a different client");
    }
    if (record.expiresAt <= Date.now()) {
      await this.store.deleteAuthorizationCode(authorizationCode);
      throw new InvalidGrantError("Authorization code has expired");
    }
    if (redirectUri && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }

    const tokenResource = this.resolveResource(resource, record.resource);
    await this.store.deleteAuthorizationCode(authorizationCode);
    return this.issueTokens(
      {
        clientId: client.client_id,
        displayName: record.displayName,
        resource: tokenResource?.href,
        scopes: record.scopes,
        userId: record.userId,
        username: record.username
      },
      true
    );
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    const record = await this.store.getRefreshToken(refreshToken);
    if (!record) {
      throw new InvalidGrantError("Invalid refresh token");
    }
    if (record.clientId !== client.client_id) {
      throw new InvalidGrantError("Refresh token was issued to a different client");
    }
    if (record.expiresAt <= Date.now()) {
      await this.store.deleteRefreshToken(refreshToken);
      throw new InvalidGrantError("Refresh token has expired");
    }

    const nextScopes = scopes?.length ? validateScopes(scopes, record.scopes) : record.scopes;
    const tokenResource = this.resolveResource(resource, record.resource);

    await this.store.deleteRefreshToken(refreshToken);
    return this.issueTokens(
      {
        clientId: client.client_id,
        displayName: record.displayName,
        resource: tokenResource?.href,
        scopes: nextScopes,
        userId: record.userId,
        username: record.username
      },
      true
    );
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    await this.store.pruneExpired();
    const record = await this.store.getAccessToken(token);
    if (!record || record.expiresAt <= Date.now()) {
      throw new InvalidGrantError("Invalid or expired access token");
    }

    return {
      clientId: record.clientId,
      expiresAt: Math.floor(record.expiresAt / 1000),
      extra: {
        displayName: record.displayName,
        userId: record.userId,
        username: record.username
      },
      resource: record.resource ? new URL(record.resource) : undefined,
      scopes: record.scopes,
      token
    };
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    const accessToken = await this.store.getAccessToken(request.token);
    if (accessToken && accessToken.clientId === client.client_id) {
      await this.store.deleteAccessToken(request.token);
      return;
    }

    const refreshToken = await this.store.getRefreshToken(request.token);
    if (refreshToken && refreshToken.clientId === client.client_id) {
      await this.store.deleteRefreshToken(request.token);
    }
  }

  private async finishAuthorization(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    session: {
      displayName: string;
      userId: string;
      username: string;
    },
    res: Response
  ): Promise<void> {
    const code = randomUUID();
    const resource = this.resolveResource(params.resource);
    const scopes = normalizeRequestedScopes(params.scopes, this.config.scope);
    const now = Date.now();
    const record: AuthorizationCodeRecord = {
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      displayName: session.displayName,
      expiresAt: now + AUTHORIZATION_CODE_TTL_MS,
      issuedAt: now,
      redirectUri: params.redirectUri,
      resource: resource?.href,
      scopes,
      userId: session.userId,
      username: session.username
    };

    await this.store.saveAuthorizationCode(code, record);

    const redirectTarget = new URL(params.redirectUri);
    redirectTarget.searchParams.set("code", code);
    if (params.state) {
      redirectTarget.searchParams.set("state", params.state);
    }
    res.redirect(302, redirectTarget.toString());
  }

  private async issueTokens(
    input: {
      clientId: string;
      displayName: string;
      resource?: string;
      scopes: string[];
      userId: string;
      username: string;
    },
    includeRefreshToken: boolean
  ): Promise<OAuthTokens> {
    const now = Date.now();
    const accessToken = randomBytes(32).toString("base64url");
    const refreshToken = includeRefreshToken
      ? randomBytes(32).toString("base64url")
      : undefined;

    const accessRecord: AccessTokenRecord = {
      clientId: input.clientId,
      displayName: input.displayName,
      expiresAt: now + this.config.accessTokenTtlSeconds * 1000,
      issuedAt: now,
      refreshToken,
      resource: input.resource,
      scopes: input.scopes,
      userId: input.userId,
      username: input.username
    };

    await this.store.saveAccessToken(accessToken, accessRecord);

    if (refreshToken) {
      const refreshRecord: RefreshTokenRecord = {
        clientId: input.clientId,
        displayName: input.displayName,
        expiresAt: now + this.config.refreshTokenTtlSeconds * 1000,
        issuedAt: now,
        resource: input.resource,
        scopes: input.scopes,
        userId: input.userId,
        username: input.username
      };
      await this.store.saveRefreshToken(refreshToken, refreshRecord);
    }

    return {
      access_token: accessToken,
      expires_in: this.config.accessTokenTtlSeconds,
      refresh_token: refreshToken,
      scope: input.scopes.join(" "),
      token_type: "bearer"
    };
  }

  private resolveResource(resource?: URL, fallback?: string): URL | undefined {
    if (resource) {
      if (!checkResourceAllowed({ configuredResource: this.resourceUrl, requestedResource: resource })) {
        throw new InvalidTargetError("Requested resource is not allowed");
      }
      return resourceUrlFromServerUrl(resource);
    }
    if (fallback) {
      return new URL(fallback);
    }
    return undefined;
  }
}

function getFormField(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeRequestedScopes(requested: string[] | undefined, supportedScope: string): string[] {
  const scopes = requested?.filter(Boolean) ?? [];
  if (scopes.length === 0) {
    return [supportedScope];
  }
  if (scopes.some((scope) => scope !== supportedScope)) {
    throw new InvalidScopeError("Only the mcp:tools scope is supported");
  }
  return [supportedScope];
}

function validateScopes(requested: string[], granted: string[]): string[] {
  if (requested.length === 0) {
    return granted;
  }
  const unknown = requested.find((scope) => !granted.includes(scope));
  if (unknown) {
    throw new InvalidScopeError("Requested scope exceeds the original grant");
  }
  return Array.from(new Set(requested));
}
