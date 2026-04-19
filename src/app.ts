import { randomBytes, randomUUID } from "node:crypto";

import {
  createOAuthMetadata,
  getOAuthProtectedResourceMetadataUrl
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  InvalidClientError,
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidRequestError,
  OAuthError,
  ServerError,
  UnsupportedGrantTypeError
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import {
  OAuthClientMetadataSchema,
  type OAuthClientInformationFull
} from "@modelcontextprotocol/sdk/shared/auth.js";

import { createServer } from "./mcp/server.js";
import type { Runtime } from "./runtime.js";
import {
  buildCsrfCookie,
  buildExpiredCsrfCookie,
  ensureCsrfToken,
  validateCsrfToken
} from "./oauth/csrf.js";
import { BunAuthorizeResponse } from "./oauth/http.js";
import {
  buildExpiredSessionCookie,
  readSessionFromCookieHeader
} from "./oauth/session.js";

const AUTH_RATE_LIMIT = {
  limit: 20,
  windowMs: 15 * 60 * 1000
} as const;

const CLIENT_REGISTRATION_RATE_LIMIT = {
  limit: 20,
  windowMs: 60 * 60 * 1000
} as const;

const MCP_RATE_LIMIT = {
  limit: 60,
  windowMs: 60 * 1000
} as const;

const TOKEN_RATE_LIMIT = {
  limit: 50,
  windowMs: 15 * 60 * 1000
} as const;

export interface BunApp {
  fetch(request: Request): Promise<Response>;
}

export function createApp(runtime: Runtime): BunApp {
  const authMetadataPath = "/.well-known/oauth-authorization-server";
  const protectedResourceMetadataPath = new URL(
    getOAuthProtectedResourceMetadataUrl(runtime.config.oauth.mcpServerUrl)
  ).pathname;
  const rateLimiter = createRateLimiter();
  const oauthMetadata = runtime.config.oauth.enabled
    ? createOAuthMetadata({
        issuerUrl: runtime.config.oauth.issuerUrl,
        provider: runtime.oauthProvider as unknown as OAuthServerProvider,
        scopesSupported: runtime.config.oauth.supportedScopes
      })
    : null;

  return {
    async fetch(request: Request): Promise<Response> {
      const startedAt = Date.now();
      let response: Response;

      try {
        response = await routeRequest(
          runtime,
          request,
          rateLimiter,
          authMetadataPath,
          protectedResourceMetadataPath,
          oauthMetadata
        );
      } catch (error) {
        runtime.logger.error(
          {
            error: serializeError(error),
            method: request.method,
            url: request.url
          },
          "request failed"
        );
        response = createJsonResponse(
          {
            error: {
              message: error instanceof Error ? error.message : String(error)
            }
          },
          500
        );
      }

      runtime.logger.info(
        {
          durationMs: Date.now() - startedAt,
          method: request.method,
          requestId: randomUUID(),
          statusCode: response.status,
          url: request.url
        },
        "request complete"
      );

      return response;
    }
  };
}

async function routeRequest(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter,
  authMetadataPath: string,
  protectedResourceMetadataPath: string,
  oauthMetadata: Record<string, unknown> | null
): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (request.method === "OPTIONS" && isCorsPath(pathname, runtime)) {
    return createCorsPreflightResponse();
  }

  if (pathname === "/healthz" && request.method === "GET") {
    return createJsonResponse({ ok: true, service: "edstem-mcp" });
  }

  if (pathname === "/readyz" && request.method === "GET") {
    return createJsonResponse({
      db: true,
      key: runtime.config.masterKey.length === 32,
      ok: true
    });
  }

  if (runtime.config.oauth.enabled) {
    if (pathname === authMetadataPath && request.method === "GET" && oauthMetadata) {
      return createJsonResponse(oauthMetadata, 200, corsHeaders());
    }

    if (pathname === protectedResourceMetadataPath && request.method === "GET") {
      return createJsonResponse(
        {
          authorization_servers: [runtime.config.oauth.issuerUrl.href],
          bearer_methods_supported: ["header"],
          resource: runtime.config.oauth.mcpServerUrl.href,
          resource_name: "EdStem MCP",
          scopes_supported: runtime.config.oauth.supportedScopes
        },
        200,
        corsHeaders()
      );
    }

    if (pathname === "/register") {
      return handleClientRegistration(runtime, request, rateLimiter);
    }

    if (pathname === "/token") {
      return handleToken(runtime, request, rateLimiter);
    }

    if (pathname === "/revoke") {
      return handleRevoke(runtime, request, rateLimiter);
    }

    if (pathname === "/authorize") {
      return handleAuthorize(runtime, request, rateLimiter);
    }
  }

  if (pathname === "/settings" && request.method === "GET") {
    return handleSettings(runtime, request);
  }

  if (pathname === "/settings/rotate" && request.method === "POST") {
    return handleSettingsRotate(runtime, request);
  }

  if (pathname === "/settings/delete" && request.method === "POST") {
    return handleSettingsDelete(runtime, request);
  }

  if (pathname === "/reconnect" && request.method === "GET") {
    return handleReconnect(runtime, request);
  }

  if (pathname === "/reconnect" && request.method === "POST") {
    return handleReconnectSubmit(runtime, request);
  }

  if (pathname === runtime.config.mcpPath) {
    return handleMcp(runtime, request, rateLimiter);
  }

  return new Response("Not found", { status: 404 });
}

async function handleAuthorize(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter
): Promise<Response> {
  if (request.method !== "GET" && request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405);
  }

  if (!rateLimiter.allow(requestKey(request, "authorize"), AUTH_RATE_LIMIT)) {
    return createOAuthErrorResponse(new InvalidRequestError("Rate limit exceeded"), 429);
  }

  const form = request.method === "POST" ? await parseFormBody(request) : undefined;
  const source =
    request.method === "POST"
      ? (form ?? {})
      : Object.fromEntries(new URL(request.url).searchParams.entries());

  try {
    const clientId = requiredField(source.client_id, "client_id");
    const responseType = requiredField(source.response_type, "response_type");
    const codeChallenge = requiredField(source.code_challenge, "code_challenge");
    const codeChallengeMethod = requiredField(
      source.code_challenge_method,
      "code_challenge_method"
    );

    if (responseType !== "code") {
      throw new InvalidRequestError("response_type must be code");
    }
    if (codeChallengeMethod !== "S256") {
      throw new InvalidRequestError("code_challenge_method must be S256");
    }

    const client = await runtime.oauthProvider.clientsStore.getClient(clientId);
    if (!client) {
      throw new InvalidClientError("Invalid client_id");
    }

    const redirectUri = resolveRedirectUri(client, source.redirect_uri);
    const response = new BunAuthorizeResponse({
      body: form,
      headers: {
        cookie: request.headers.get("cookie") ?? undefined
      },
      method: request.method
    });

    await runtime.oauthProvider.authorize(
      client,
      {
        codeChallenge,
        redirectUri,
        resource: source.resource ? new URL(source.resource) : undefined,
        scopes: source.scope ? source.scope.split(" ").filter(Boolean) : undefined,
        state: source.state
      },
      response
    );

    return response.toResponse();
  } catch (error) {
    if (error instanceof OAuthError) {
      return createOAuthErrorResponse(error);
    }
    const serverError = new ServerError(error instanceof Error ? error.message : String(error));
    return createOAuthErrorResponse(serverError, 500);
  }
}

async function handleClientRegistration(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter
): Promise<Response> {
  if (request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405, corsHeaders());
  }

  if (!rateLimiter.allow(requestKey(request, "register"), CLIENT_REGISTRATION_RATE_LIMIT)) {
    return createOAuthErrorResponse(new InvalidRequestError("Rate limit exceeded"), 429, corsHeaders());
  }

  try {
    const body = (await request.json()) as unknown;
    const parsed = OAuthClientMetadataSchema.safeParse(body);
    if (!parsed.success) {
      throw new InvalidClientMetadataError(parsed.error.message);
    }

    const metadata = parsed.data;
    const isPublicClient = metadata.token_endpoint_auth_method === "none";
    const issuedAt = Math.floor(Date.now() / 1000);
    const registerClient = runtime.oauthProvider.clientsStore.registerClient;
    if (!registerClient) {
      throw new ServerError("Client registration is not supported");
    }

    const client: OAuthClientInformationFull = await registerClient.call(
      runtime.oauthProvider.clientsStore,
      {
      ...metadata,
      client_secret: isPublicClient ? undefined : randomBytes(32).toString("hex"),
      client_secret_expires_at: isPublicClient ? undefined : issuedAt + 30 * 24 * 60 * 60
      }
    );

    return createJsonResponse(client, 201, corsHeaders({ "Cache-Control": "no-store" }));
  } catch (error) {
    if (error instanceof OAuthError) {
      return createOAuthErrorResponse(error, undefined, corsHeaders());
    }
    const serverError = new ServerError(error instanceof Error ? error.message : String(error));
    return createOAuthErrorResponse(serverError, 500, corsHeaders());
  }
}

async function handleToken(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter
): Promise<Response> {
  if (request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405, corsHeaders());
  }

  if (!rateLimiter.allow(requestKey(request, "token"), TOKEN_RATE_LIMIT)) {
    return createOAuthErrorResponse(new InvalidRequestError("Rate limit exceeded"), 429, corsHeaders());
  }

  try {
    const body = await parseFormBody(request);
    const client = await authenticateClient(runtime, request, body);
    const grantType = requiredField(body.grant_type, "grant_type");

    switch (grantType) {
      case "authorization_code": {
        const code = requiredField(body.code, "code");
        const codeVerifier = requiredField(body.code_verifier, "code_verifier");

        if (!runtime.oauthProvider.skipLocalPkceValidation) {
          const codeChallenge = await runtime.oauthProvider.challengeForAuthorizationCode(client, code);
          const valid = await verifyPkceChallenge(codeVerifier, codeChallenge);
          if (!valid) {
            throw new InvalidGrantError("code_verifier does not match the challenge");
          }
        }

        const tokens = await runtime.oauthProvider.exchangeAuthorizationCode(
          client,
          code,
          runtime.oauthProvider.skipLocalPkceValidation ? codeVerifier : undefined,
          body.redirect_uri,
          body.resource ? new URL(body.resource) : undefined
        );
        return createJsonResponse(tokens, 200, corsHeaders({ "Cache-Control": "no-store" }));
      }

      case "refresh_token": {
        const refreshToken = requiredField(body.refresh_token, "refresh_token");
        const tokens = await runtime.oauthProvider.exchangeRefreshToken(
          client,
          refreshToken,
          body.scope ? body.scope.split(" ").filter(Boolean) : undefined,
          body.resource ? new URL(body.resource) : undefined
        );
        return createJsonResponse(tokens, 200, corsHeaders({ "Cache-Control": "no-store" }));
      }

      default:
        throw new UnsupportedGrantTypeError("Unsupported grant type");
    }
  } catch (error) {
    if (error instanceof OAuthError) {
      return createOAuthErrorResponse(error, undefined, corsHeaders());
    }
    const serverError = new ServerError(error instanceof Error ? error.message : String(error));
    return createOAuthErrorResponse(serverError, 500, corsHeaders());
  }
}

async function handleRevoke(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter
): Promise<Response> {
  if (request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405, corsHeaders());
  }

  if (!rateLimiter.allow(requestKey(request, "revoke"), TOKEN_RATE_LIMIT)) {
    return createOAuthErrorResponse(new InvalidRequestError("Rate limit exceeded"), 429, corsHeaders());
  }

  try {
    const body = await parseFormBody(request);
    const client = await authenticateClient(runtime, request, body);
    const token = requiredField(body.token, "token");

    if (runtime.oauthProvider.revokeToken) {
      await runtime.oauthProvider.revokeToken(client, { token });
    }

    return new Response(null, {
      headers: corsHeaders({ "Cache-Control": "no-store" }),
      status: 200
    });
  } catch (error) {
    if (error instanceof OAuthError) {
      return createOAuthErrorResponse(error, undefined, corsHeaders());
    }
    const serverError = new ServerError(error instanceof Error ? error.message : String(error));
    return createOAuthErrorResponse(serverError, 500, corsHeaders());
  }
}

async function handleMcp(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter
): Promise<Response> {
  if (!rateLimiter.allow(requestKey(request, "mcp"), MCP_RATE_LIMIT)) {
    return createJsonResponse(
      {
        error: {
          message: "Rate limit exceeded."
        }
      },
      429
    );
  }

  let authInfo: AuthInfo | undefined;
  if (runtime.config.oauth.enabled) {
    const auth = await authenticateBearerRequest(runtime, request);
    if (auth instanceof Response) {
      return auth;
    }
    authInfo = auth;
  }

  const transport = new WebStandardStreamableHTTPServerTransport({
    enableJsonResponse: true,
    sessionIdGenerator: undefined
  });
  const server = createServer(runtime.config, runtime.credentials);
  await server.connect(transport);
  return transport.handleRequest(request, { authInfo });
}

function handleSettings(runtime: Runtime, request: Request): Response {
  const session = readSessionFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  const headers = new Headers();
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
  }

  if (!session) {
    return createHtmlResponse(renderSessionRequiredPage("settings"), 401, headers);
  }

  return createHtmlResponse(
    renderSettingsPage({
      csrfToken: csrf.token,
      session,
      status: runtime.credentials.getConnectionStatus(session.userId)
    }),
    200,
    headers
  );
}

async function handleSettingsRotate(runtime: Runtime, request: Request): Promise<Response> {
  const session = readSessionFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  const headers = new Headers();
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
  }

  if (!session) {
    return createHtmlResponse(renderSessionRequiredPage("settings"), 401, headers);
  }

  const body = await parseFormBody(request);
  if (!validateCsrfToken(request.headers.get("cookie") ?? undefined, body.csrf_token)) {
    return createHtmlResponse(
      renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: "Your session expired. Reload the page and try again.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      403,
      headers
    );
  }

  const edToken = body.ed_token?.trim() || "";
  if (!edToken) {
    return createHtmlResponse(
      renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: "Ed API token is required.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      422,
      headers
    );
  }

  try {
    await runtime.credentials.connect(session.userId, edToken);
    return redirectResponse("/settings", headers);
  } catch (error) {
    return createHtmlResponse(
      renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: error instanceof Error ? error.message : String(error),
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      422,
      headers
    );
  }
}

async function handleSettingsDelete(runtime: Runtime, request: Request): Promise<Response> {
  const session = readSessionFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  const headers = new Headers();
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
  }

  if (!session) {
    return createHtmlResponse(renderSessionRequiredPage("settings"), 401, headers);
  }

  const body = await parseFormBody(request);
  if (!validateCsrfToken(request.headers.get("cookie") ?? undefined, body.csrf_token)) {
    return createHtmlResponse(
      renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: "Your session expired. Reload the page and try again.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      403,
      headers
    );
  }

  runtime.credentials.delete(session.userId);
  runtime.users.deleteAccount(session.userId);
  headers.append("Set-Cookie", buildExpiredSessionCookie(runtime.config.oauth));
  headers.append("Set-Cookie", buildExpiredCsrfCookie(runtime.config.oauth));

  return createHtmlResponse(renderDeletedPage(), 200, headers);
}

function handleReconnect(runtime: Runtime, request: Request): Response {
  const session = readSessionFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  const headers = new Headers();
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
  }

  if (!session) {
    return createHtmlResponse(renderSessionRequiredPage("reconnect"), 401, headers);
  }

  return createHtmlResponse(
    renderReconnectPage({
      csrfToken: csrf.token,
      session,
      status: runtime.credentials.getConnectionStatus(session.userId)
    }),
    200,
    headers
  );
}

async function handleReconnectSubmit(runtime: Runtime, request: Request): Promise<Response> {
  const session = readSessionFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  const headers = new Headers();
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
  }

  if (!session) {
    return createHtmlResponse(renderSessionRequiredPage("reconnect"), 401, headers);
  }

  const body = await parseFormBody(request);
  if (!validateCsrfToken(request.headers.get("cookie") ?? undefined, body.csrf_token)) {
    return createHtmlResponse(
      renderReconnectPage({
        csrfToken: csrf.token,
        errorMessage: "Your session expired. Reload the page and try again.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      403,
      headers
    );
  }

  const edToken = body.ed_token?.trim() || "";
  if (!edToken) {
    return createHtmlResponse(
      renderReconnectPage({
        csrfToken: csrf.token,
        errorMessage: "Ed API token is required.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      422,
      headers
    );
  }

  try {
    await runtime.credentials.connect(session.userId, edToken);
    return redirectResponse("/settings", headers);
  } catch (error) {
    return createHtmlResponse(
      renderReconnectPage({
        csrfToken: csrf.token,
        errorMessage: error instanceof Error ? error.message : String(error),
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      422,
      headers
    );
  }
}

async function authenticateBearerRequest(
  runtime: Runtime,
  request: Request
): Promise<AuthInfo | Response> {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) {
    return unauthorizedResponse(runtime, "Bearer token is required.");
  }

  try {
    const authInfo = await runtime.oauthProvider.verifyAccessToken(
      authorization.slice("Bearer ".length)
    );
    if (!authInfo.scopes.includes(runtime.config.oauth.readScope)) {
      return forbiddenResponse("Read scope is required.");
    }
    return authInfo;
  } catch (error) {
    return unauthorizedResponse(
      runtime,
      error instanceof Error ? error.message : "Invalid bearer token."
    );
  }
}

async function authenticateClient(
  runtime: Runtime,
  request: Request,
  body: Record<string, string>
): Promise<OAuthClientInformationFull> {
  const basic = request.headers.get("authorization");
  let clientId = body.client_id;
  let clientSecret = body.client_secret;

  if (basic?.startsWith("Basic ")) {
    const decoded = atob(basic.slice("Basic ".length));
    const separator = decoded.indexOf(":");
    clientId = separator >= 0 ? decoded.slice(0, separator) : decoded;
    clientSecret = separator >= 0 ? decoded.slice(separator + 1) : "";
  }

  if (!clientId) {
    throw new InvalidClientError("client_id is required");
  }

  const client = await runtime.oauthProvider.clientsStore.getClient(clientId);
  if (!client) {
    throw new InvalidClientError("Invalid client_id");
  }

  const authMethod = client.token_endpoint_auth_method ?? "client_secret_basic";
  if (authMethod === "none") {
    return client;
  }

  if (!clientSecret || client.client_secret !== clientSecret) {
    throw new InvalidClientError("Client authentication failed");
  }

  return client;
}

async function parseFormBody(request: Request): Promise<Record<string, string>> {
  const formData = await request.formData();
  const body: Record<string, string> = {};

  for (const [key, value] of formData.entries()) {
    if (typeof value === "string") {
      body[key] = value;
    }
  }

  return body;
}

function resolveRedirectUri(
  client: OAuthClientInformationFull,
  requestedRedirectUri?: string
): string {
  if (requestedRedirectUri) {
    if (!client.redirect_uris.includes(requestedRedirectUri)) {
      throw new InvalidRequestError("Unregistered redirect_uri");
    }
    return requestedRedirectUri;
  }

  if (client.redirect_uris.length !== 1) {
    throw new InvalidRequestError(
      "redirect_uri must be provided when multiple redirect URIs are registered"
    );
  }

  return client.redirect_uris[0]!;
}

async function verifyPkceChallenge(
  codeVerifier: string,
  codeChallenge: string
): Promise<boolean> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier)
  );
  const encoded = Buffer.from(digest).toString("base64url");
  return encoded === codeChallenge;
}

function createJsonResponse(
  body: unknown,
  status: number = 200,
  headers?: HeadersInit
): Response {
  const resolvedHeaders = new Headers(headers);
  if (!resolvedHeaders.has("Content-Type")) {
    resolvedHeaders.set("Content-Type", "application/json");
  }

  return new Response(JSON.stringify(body), {
    headers: resolvedHeaders,
    status
  });
}

function createHtmlResponse(
  html: string,
  status: number = 200,
  headers?: Headers
): Response {
  const resolvedHeaders = headers ?? new Headers();
  if (!resolvedHeaders.has("Content-Type")) {
    resolvedHeaders.set("Content-Type", "text/html; charset=utf-8");
  }

  return new Response(html, {
    headers: resolvedHeaders,
    status
  });
}

function redirectResponse(location: string, headers?: Headers): Response {
  const resolvedHeaders = headers ?? new Headers();
  resolvedHeaders.set("Location", location);
  return new Response(null, {
    headers: resolvedHeaders,
    status: 302
  });
}

function createCorsPreflightResponse(): Response {
  return new Response(null, {
    headers: corsHeaders(),
    status: 204
  });
}

function corsHeaders(extra?: Record<string, string>): Headers {
  return new Headers({
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Origin": "*",
    ...(extra ?? {})
  });
}

function createOAuthErrorResponse(
  error: OAuthError,
  status?: number,
  headers?: Headers
): Response {
  const resolvedHeaders = headers ?? new Headers();
  resolvedHeaders.set("Cache-Control", "no-store");
  return createJsonResponse(
    error.toResponseObject(),
    status ?? (error instanceof ServerError ? 500 : 400),
    resolvedHeaders
  );
}

function unauthorizedResponse(runtime: Runtime, message: string): Response {
  return createJsonResponse(
    {
      error: "unauthorized",
      error_description: message
    },
    401,
    {
      "WWW-Authenticate": `Bearer resource_metadata="${getOAuthProtectedResourceMetadataUrl(
        runtime.config.oauth.mcpServerUrl
      )}"`
    }
  );
}

function forbiddenResponse(message: string): Response {
  return createJsonResponse(
    {
      error: "insufficient_scope",
      error_description: message
    },
    403
  );
}

function requestKey(request: Request, namespace: string): string {
  const forwardedFor =
    request.headers.get("x-forwarded-for") ??
    request.headers.get("x-real-ip") ??
    "anonymous";
  return `${namespace}:${forwardedFor}`;
}

type RateLimitConfig = {
  limit: number;
  windowMs: number;
};

type RateLimiter = {
  allow(key: string, config: RateLimitConfig): boolean;
};

function createRateLimiter(): RateLimiter {
  const hits = new Map<string, number[]>();

  return {
    allow(key, config) {
      const now = Date.now();
      const current = hits.get(key) ?? [];
      const next = current.filter((timestamp) => now - timestamp < config.windowMs);
      if (next.length >= config.limit) {
        hits.set(key, next);
        return false;
      }
      next.push(now);
      hits.set(key, next);
      return true;
    }
  };
}

function isCorsPath(pathname: string, runtime: Runtime): boolean {
  if (!runtime.config.oauth.enabled) {
    return false;
  }

  return (
    pathname === "/register" ||
    pathname === "/token" ||
    pathname === "/revoke" ||
    pathname === "/.well-known/oauth-authorization-server" ||
    pathname ===
      new URL(getOAuthProtectedResourceMetadataUrl(runtime.config.oauth.mcpServerUrl)).pathname
  );
}

function requiredField(value: string | undefined, name: string): string {
  if (!value) {
    throw new InvalidRequestError(`${name} is required`);
  }
  return value;
}

function serializeError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    return {
      message: error.message,
      name: error.name,
      stack: error.stack
    };
  }

  return {
    value: String(error)
  };
}

function renderSessionRequiredPage(kind: "settings" | "reconnect"): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>EdStem MCP</title></head>
  <body>
    <main>
      <h1>Sign in first</h1>
      <p>Open this page from a browser session that already authorized EdStem MCP.</p>
      <p>Then return to <code>${escapeHtml(kind)}</code>.</p>
    </main>
  </body>
</html>`;
}

function renderDeletedPage(): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Account deleted</title></head>
  <body><main><h1>Account deleted</h1></main></body>
</html>`;
}

function renderSettingsPage(options: {
  csrfToken: string;
  errorMessage?: string;
  session: { displayName: string; email: string; userId: number };
  status: { connected: boolean; edUserName?: string; isInvalid: boolean; lastVerifiedAt?: number };
}): string {
  return simplePage(
    "Settings",
    `
      <h1>Connection</h1>
      <p>Signed in as <strong>${escapeHtml(options.session.displayName)}</strong> (${escapeHtml(options.session.email)})</p>
      <p>Status: ${options.status.connected ? (options.status.isInvalid ? "needs reconnect" : `connected as ${escapeHtml(options.status.edUserName ?? "")}`) : "not connected"}</p>
      ${options.errorMessage ? `<p class="error">${escapeHtml(options.errorMessage)}</p>` : ""}
      <form method="post" action="/settings/rotate">
        <input type="hidden" name="csrf_token" value="${escapeHtml(options.csrfToken)}">
        <label>Rotate Ed token</label>
        <input type="password" name="ed_token" autocomplete="off">
        <button type="submit">Update</button>
      </form>
      <form method="post" action="/settings/delete" onsubmit="return confirm('Delete this account?');">
        <input type="hidden" name="csrf_token" value="${escapeHtml(options.csrfToken)}">
        <button type="submit">Delete account</button>
      </form>
    `
  );
}

function renderReconnectPage(options: {
  csrfToken: string;
  errorMessage?: string;
  session: { displayName: string; email: string; userId: number };
  status: { connected: boolean; edUserName?: string; isInvalid: boolean; lastVerifiedAt?: number };
}): string {
  return simplePage(
    "Reconnect",
    `
      <h1>Reconnect Ed</h1>
      <p>${escapeHtml(options.session.displayName)} (${escapeHtml(options.session.email)})</p>
      <p>Status: ${options.status.connected && !options.status.isInvalid ? `connected as ${escapeHtml(options.status.edUserName ?? "")}` : "needs Ed token"}</p>
      ${options.errorMessage ? `<p class="error">${escapeHtml(options.errorMessage)}</p>` : ""}
      <form method="post" action="/reconnect">
        <input type="hidden" name="csrf_token" value="${escapeHtml(options.csrfToken)}">
        <label>Ed API token</label>
        <input type="password" name="ed_token" autocomplete="off">
        <button type="submit">Reconnect</button>
      </form>
    `
  );
}

function simplePage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: system-ui, sans-serif; background: #f4efe5; color: #1e1b16; margin: 0; }
      main { max-width: 40rem; margin: 3rem auto; padding: 2rem; background: white; border-radius: 1rem; }
      input, button { display: block; width: 100%; margin: 0.5rem 0 1rem; padding: 0.75rem; }
      .error { color: #a53d2b; }
    </style>
  </head>
  <body><main>${body}</main></body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
