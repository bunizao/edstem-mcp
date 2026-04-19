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
  TemporarilyUnavailableError,
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
import { renderAuthorizePage as renderAuthorizeHtml } from "./oauth/login-page.js";
import {
  buildSessionCookie,
  buildExpiredSessionCookie,
  createSessionForUser,
  readSessionStateFromCookieHeader
} from "./oauth/session.js";
import {
  EdIdentityMismatchError
} from "./users/service.js";
import { verifyEdToken } from "./credentials/verifier.js";

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

const AUTHORIZE_ATTEMPT_RATE_LIMIT = {
  limit: 5,
  windowMs: 15 * 60 * 1000
} as const;

const ED_TOKEN_ATTEMPT_RATE_LIMIT = {
  limit: 5,
  windowMs: 15 * 60 * 1000
} as const;

export interface BunApp {
  fetch(request: Request): Promise<Response>;
}

type RequestContext = {
  clientIp: string;
  requestId: string;
};

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
      const requestId = randomUUID();
      const clientIp = getClientIp(request);
      const context: RequestContext = {
        clientIp,
        requestId
      };
      let response: Response;

      try {
        response = await routeRequest(
          runtime,
          request,
          rateLimiter,
          context,
          authMetadataPath,
          protectedResourceMetadataPath,
          oauthMetadata
        );
      } catch (error) {
        runtime.logger.error(
          {
            clientIp,
            error: serializeError(error),
            method: request.method,
            requestId,
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

      response.headers.set("X-Request-Id", requestId);
      runtime.logger.info(
        {
          clientIp,
          durationMs: Date.now() - startedAt,
          method: request.method,
          requestId,
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
  context: RequestContext,
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
      return handleClientRegistration(runtime, request, rateLimiter, context);
    }

    if (pathname === "/token") {
      return handleToken(runtime, request, rateLimiter, context);
    }

    if (pathname === "/revoke") {
      return handleRevoke(runtime, request, rateLimiter, context);
    }

    if (pathname === "/authorize") {
      return handleAuthorize(runtime, request, rateLimiter, context);
    }
  }

  if (pathname === "/settings" && request.method === "GET") {
    return handleSettings(runtime, request);
  }

  if (pathname === "/settings/rotate" && request.method === "POST") {
    return handleSettingsRotate(runtime, request, rateLimiter, context);
  }

  if (pathname === "/settings/delete" && request.method === "POST") {
    return handleSettingsDelete(runtime, request);
  }

  if (pathname === "/reconnect" && request.method === "GET") {
    return handleReconnect(runtime, request);
  }

  if (pathname === "/reconnect" && request.method === "POST") {
    return handleReconnectSubmit(runtime, request, rateLimiter, context);
  }

  if (pathname === runtime.config.mcpPath) {
    return handleMcp(runtime, request, rateLimiter, context);
  }

  return new Response("Not found", { status: 404 });
}

async function handleAuthorize(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  if (request.method !== "GET" && request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405);
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

    const requestedScopes = parseRequestedScopes(source.scope, runtime.config);
    const sessionState = readSessionStateFromCookieHeader(
      request.headers.get("cookie") ?? undefined,
      runtime.config.oauth
    );
    const redirectUri = resolveRedirectUri(client, source.redirect_uri);
    const response = new BunAuthorizeResponse({
      body: form,
      headers: {
        cookie: request.headers.get("cookie") ?? undefined
      },
      method: request.method
    });
    if (sessionState.reason === "expired" || sessionState.reason === "invalid") {
      response.appendHeader("Set-Cookie", buildExpiredSessionCookie(runtime.config.oauth));
    }

    if (!rateLimiter.allow(requestKey(request, "authorize"), AUTH_RATE_LIMIT)) {
      runtime.logger.warn(
        {
          clientId,
          clientIp: context.clientIp,
          event: "oauth.authorize.throttled",
          requestId: context.requestId
        },
        "oauth authorize throttled"
      );
      return createAuthorizeRateLimitResponse(
        runtime,
        client,
        {
          codeChallenge,
          redirectUri,
          resource: source.resource ? new URL(source.resource) : undefined,
          scopes: requestedScopes,
          state: source.state
        },
        form,
        request.method === "POST" ? sessionState : { reason: "missing", session: null },
        request.headers.get("cookie") ?? undefined,
        AUTH_RATE_LIMIT
      );
    }

    if (
      request.method === "POST" &&
      !rateLimiter.allow(
        buildAuthorizeAttemptKey(request, sessionState.session),
        AUTHORIZE_ATTEMPT_RATE_LIMIT
      )
    ) {
      runtime.logger.warn(
        {
          clientId,
          clientIp: context.clientIp,
          event: "oauth.authorize.attempt_throttled",
          requestId: context.requestId
        },
        "oauth authorize attempt throttled"
      );
      return createAuthorizeRateLimitResponse(
        runtime,
        client,
        {
          codeChallenge,
          redirectUri,
          resource: source.resource ? new URL(source.resource) : undefined,
          scopes: requestedScopes,
          state: source.state
        },
        form,
        sessionState,
        request.headers.get("cookie") ?? undefined,
        AUTHORIZE_ATTEMPT_RATE_LIMIT
      );
    }

    await runtime.oauthProvider.authorize(
      client,
      {
        codeChallenge,
        redirectUri,
        resource: source.resource ? new URL(source.resource) : undefined,
        scopes: requestedScopes,
        state: source.state
      },
      response
    );

    return response.toResponse();
  } catch (error) {
    if (error instanceof OAuthError) {
      runtime.logger.warn(
        {
          clientIp: context.clientIp,
          error: serializeError(error),
          event: "oauth.authorize.failed",
          requestId: context.requestId
        },
        "oauth authorize failed"
      );
      return createOAuthErrorResponse(error);
    }
    runtime.logger.error(
      {
        clientIp: context.clientIp,
        error: serializeError(error),
        event: "oauth.authorize.crashed",
        requestId: context.requestId
      },
      "oauth authorize crashed"
    );
    const serverError = new ServerError(error instanceof Error ? error.message : String(error));
    return createOAuthErrorResponse(serverError, 500);
  }
}

async function handleClientRegistration(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  if (request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405, corsHeaders());
  }

  if (!rateLimiter.allow(requestKey(request, "register"), CLIENT_REGISTRATION_RATE_LIMIT)) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        event: "oauth.client_registration.throttled",
        requestId: context.requestId
      },
      "oauth client registration throttled"
    );
    return createOAuthErrorResponse(
      new TemporarilyUnavailableError("Too many client registration attempts."),
      429,
      withRetryAfterHeaders(CLIENT_REGISTRATION_RATE_LIMIT, corsHeaders())
    );
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

    runtime.logger.info(
      {
        clientId: client.client_id,
        clientIp: context.clientIp,
        event: "oauth.client_registration.created",
        requestId: context.requestId
      },
      "oauth client registered"
    );

    return createJsonResponse(client, 201, corsHeaders({ "Cache-Control": "no-store" }));
  } catch (error) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        error: serializeError(error),
        event: "oauth.client_registration.failed",
        requestId: context.requestId
      },
      "oauth client registration failed"
    );
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
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  if (request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405, corsHeaders());
  }

  if (!rateLimiter.allow(requestKey(request, "token"), TOKEN_RATE_LIMIT)) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        event: "oauth.token.throttled",
        requestId: context.requestId
      },
      "oauth token throttled"
    );
    return createOAuthErrorResponse(
      new TemporarilyUnavailableError("Too many token requests."),
      429,
      withRetryAfterHeaders(TOKEN_RATE_LIMIT, corsHeaders())
    );
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
        runtime.logger.info(
          {
            clientId: client.client_id,
            clientIp: context.clientIp,
            event: "oauth.token.issued",
            grantType,
            requestId: context.requestId
          },
          "oauth token issued"
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
        runtime.logger.info(
          {
            clientId: client.client_id,
            clientIp: context.clientIp,
            event: "oauth.token.refreshed",
            grantType,
            requestId: context.requestId
          },
          "oauth token refreshed"
        );
        return createJsonResponse(tokens, 200, corsHeaders({ "Cache-Control": "no-store" }));
      }

      default:
        throw new UnsupportedGrantTypeError("Unsupported grant type");
    }
  } catch (error) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        error: serializeError(error),
        event: "oauth.token.failed",
        requestId: context.requestId
      },
      "oauth token failed"
    );
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
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  if (request.method !== "POST") {
    return createOAuthErrorResponse(new InvalidRequestError("Method not allowed"), 405, corsHeaders());
  }

  if (!rateLimiter.allow(requestKey(request, "revoke"), TOKEN_RATE_LIMIT)) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        event: "oauth.revoke.throttled",
        requestId: context.requestId
      },
      "oauth revoke throttled"
    );
    return createOAuthErrorResponse(
      new TemporarilyUnavailableError("Too many token revocation attempts."),
      429,
      withRetryAfterHeaders(TOKEN_RATE_LIMIT, corsHeaders())
    );
  }

  try {
    const body = await parseFormBody(request);
    const client = await authenticateClient(runtime, request, body);
    const token = requiredField(body.token, "token");

    if (runtime.oauthProvider.revokeToken) {
      await runtime.oauthProvider.revokeToken(client, { token });
    }

    runtime.logger.info(
      {
        clientId: client.client_id,
        clientIp: context.clientIp,
        event: "oauth.revoke.completed",
        requestId: context.requestId
      },
      "oauth token revoked"
    );

    return new Response(null, {
      headers: corsHeaders({ "Cache-Control": "no-store" }),
      status: 200
    });
  } catch (error) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        error: serializeError(error),
        event: "oauth.revoke.failed",
        requestId: context.requestId
      },
      "oauth revoke failed"
    );
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
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  if (!rateLimiter.allow(requestKey(request, "mcp"), MCP_RATE_LIMIT)) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        event: "mcp.throttled",
        requestId: context.requestId
      },
      "mcp throttled"
    );
    return createJsonResponse(
      {
        error: {
          message: "Rate limit exceeded."
        }
      },
      429,
      withRetryAfterHeaders(MCP_RATE_LIMIT)
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
  const sessionState = readSessionStateFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const session = sessionState.session;
  const headers = new Headers();

  if (!session) {
    appendSessionCleanupCookies(headers, runtime.config.oauth, sessionState.reason);
    return createHtmlResponse(
      renderSessionRequiredPage("settings", sessionState.reason),
      401,
      headers
    );
  }

  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
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

async function handleSettingsRotate(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  const sessionState = readSessionStateFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const session = sessionState.session;
  const headers = new Headers();

  if (!session) {
    appendSessionCleanupCookies(headers, runtime.config.oauth, sessionState.reason);
    return createHtmlResponse(
      renderSessionRequiredPage("settings", sessionState.reason),
      401,
      headers
    );
  }

  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
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

  if (
    !rateLimiter.allow(
      requestKey(request, "settings-rotate", String(session.userId)),
      ED_TOKEN_ATTEMPT_RATE_LIMIT
    )
  ) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        event: "settings.rotate.throttled",
        requestId: context.requestId,
        userId: session.userId
      },
      "settings rotate throttled"
    );
    return createHtmlResponse(
      renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: "Too many Ed token attempts. Wait a bit and try again.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      429,
      withRetryAfterHeaders(ED_TOKEN_ATTEMPT_RATE_LIMIT, headers)
    );
  }

  try {
    const verified = await verifyEdToken(edToken, runtime.config.apiBaseUrl);
    const user = runtime.users.syncIdentity(session.userId, verified);
    runtime.credentials.connectVerified(user.id, edToken, verified);
    headers.append(
      "Set-Cookie",
      buildSessionCookie(
        createSessionForUser(user, runtime.config.oauth.sessionTtlSeconds),
        runtime.config.oauth
      )
    );
    runtime.logger.info(
      {
        clientIp: context.clientIp,
        event: "settings.rotate.succeeded",
        requestId: context.requestId,
        userId: session.userId
      },
      "settings rotate succeeded"
    );
    return redirectResponse("/settings", headers);
  } catch (error) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        error: serializeError(error),
        event: "settings.rotate.failed",
        requestId: context.requestId,
        userId: session.userId
      },
      "settings rotate failed"
    );
    return createHtmlResponse(
      renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: mapEdConnectionError(error),
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      422,
      headers
    );
  }
}

async function handleSettingsDelete(runtime: Runtime, request: Request): Promise<Response> {
  const sessionState = readSessionStateFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const session = sessionState.session;
  const headers = new Headers();

  if (!session) {
    appendSessionCleanupCookies(headers, runtime.config.oauth, sessionState.reason);
    return createHtmlResponse(
      renderSessionRequiredPage("settings", sessionState.reason),
      401,
      headers
    );
  }

  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
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
  const sessionState = readSessionStateFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const session = sessionState.session;
  const headers = new Headers();

  if (!session) {
    appendSessionCleanupCookies(headers, runtime.config.oauth, sessionState.reason);
    return createHtmlResponse(
      renderSessionRequiredPage("reconnect", sessionState.reason),
      401,
      headers
    );
  }

  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
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

async function handleReconnectSubmit(
  runtime: Runtime,
  request: Request,
  rateLimiter: RateLimiter,
  context: RequestContext
): Promise<Response> {
  const sessionState = readSessionStateFromCookieHeader(
    request.headers.get("cookie") ?? undefined,
    runtime.config.oauth
  );
  const session = sessionState.session;
  const headers = new Headers();

  if (!session) {
    appendSessionCleanupCookies(headers, runtime.config.oauth, sessionState.reason);
    return createHtmlResponse(
      renderSessionRequiredPage("reconnect", sessionState.reason),
      401,
      headers
    );
  }

  const csrf = ensureCsrfToken(request.headers.get("cookie") ?? undefined);
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
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

  if (
    !rateLimiter.allow(
      requestKey(request, "reconnect", String(session.userId)),
      ED_TOKEN_ATTEMPT_RATE_LIMIT
    )
  ) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        event: "reconnect.throttled",
        requestId: context.requestId,
        userId: session.userId
      },
      "reconnect throttled"
    );
    return createHtmlResponse(
      renderReconnectPage({
        csrfToken: csrf.token,
        errorMessage: "Too many Ed token attempts. Wait a bit and try again.",
        session,
        status: runtime.credentials.getConnectionStatus(session.userId)
      }),
      429,
      withRetryAfterHeaders(ED_TOKEN_ATTEMPT_RATE_LIMIT, headers)
    );
  }

  try {
    const verified = await verifyEdToken(edToken, runtime.config.apiBaseUrl);
    const user = runtime.users.syncIdentity(session.userId, verified);
    runtime.credentials.connectVerified(user.id, edToken, verified);
    headers.append(
      "Set-Cookie",
      buildSessionCookie(
        createSessionForUser(user, runtime.config.oauth.sessionTtlSeconds),
        runtime.config.oauth
      )
    );
    runtime.logger.info(
      {
        clientIp: context.clientIp,
        event: "reconnect.succeeded",
        requestId: context.requestId,
        userId: session.userId
      },
      "reconnect succeeded"
    );
    return redirectResponse("/settings", headers);
  } catch (error) {
    runtime.logger.warn(
      {
        clientIp: context.clientIp,
        error: serializeError(error),
        event: "reconnect.failed",
        requestId: context.requestId,
        userId: session.userId
      },
      "reconnect failed"
    );
    return createHtmlResponse(
      renderReconnectPage({
        csrfToken: csrf.token,
        errorMessage: mapEdConnectionError(error),
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
    return unauthorizedResponse(runtime, "Bearer token is required.", "invalid_token");
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
      error instanceof Error ? error.message : "Invalid bearer token.",
      "invalid_token"
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
  if (!resolvedHeaders.has("Cache-Control")) {
    resolvedHeaders.set("Cache-Control", "no-store");
  }
  if (!resolvedHeaders.has("Content-Security-Policy")) {
    resolvedHeaders.set(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
  }
  if (!resolvedHeaders.has("Referrer-Policy")) {
    resolvedHeaders.set("Referrer-Policy", "no-referrer");
  }
  if (!resolvedHeaders.has("X-Frame-Options")) {
    resolvedHeaders.set("X-Frame-Options", "DENY");
  }

  return new Response(html, {
    headers: resolvedHeaders,
    status
  });
}

function redirectResponse(location: string, headers?: Headers): Response {
  const resolvedHeaders = headers ?? new Headers();
  resolvedHeaders.set("Cache-Control", "no-store");
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

function unauthorizedResponse(
  runtime: Runtime,
  message: string,
  errorCode: "invalid_token" | "invalid_request"
): Response {
  return createJsonResponse(
    {
      error: "unauthorized",
      error_description: message
    },
    401,
    {
      "Cache-Control": "no-store",
      "WWW-Authenticate": `Bearer error="${errorCode}", error_description="${escapeAttribute(
        message
      )}", resource_metadata="${getOAuthProtectedResourceMetadataUrl(
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
    403,
    {
      "Cache-Control": "no-store"
    }
  );
}

function requestKey(request: Request, namespace: string, subject?: string): string {
  const keyParts = [namespace, getClientIp(request)];
  if (subject) {
    keyParts.push(subject);
  }
  return keyParts.join(":");
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

function withRetryAfterHeaders(
  config: RateLimitConfig,
  headers: HeadersInit = new Headers()
): Headers {
  const resolvedHeaders = new Headers(headers);
  resolvedHeaders.set("Retry-After", String(Math.ceil(config.windowMs / 1000)));
  return resolvedHeaders;
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

function getClientIp(request: Request): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    const first = forwardedFor.split(",")[0]?.trim();
    if (first) {
      return first;
    }
  }

  const realIp = request.headers.get("x-real-ip")?.trim();
  return realIp || "anonymous";
}

function parseRequestedScopes(
  scope: string | undefined,
  config: Runtime["config"]
): string[] {
  return scope?.split(" ").filter(Boolean) || [config.oauth.readScope];
}

function buildAuthorizeAttemptKey(
  request: Request,
  session: { email: string; userId: number } | null
): string {
  return requestKey(
    request,
    "authorize-attempt",
    normalizeRateLimitIdentity(session ? String(session.userId) : undefined)
  );
}

function normalizeRateLimitIdentity(value: string | undefined): string {
  const trimmed = value?.trim().toLowerCase();
  return trimmed || "anonymous";
}

function createAuthorizeRateLimitResponse(
  runtime: Runtime,
  client: OAuthClientInformationFull,
  params: {
    codeChallenge: string;
    redirectUri: string;
    resource?: URL;
    scopes: string[];
    state?: string;
  },
  form: Record<string, string> | undefined,
  sessionState: {
    reason: "missing" | "expired" | "invalid" | "valid";
    session: { displayName: string; email: string; userId: number } | null;
  },
  cookieHeader: string | undefined,
  rateLimit: RateLimitConfig
): Response {
  const headers = withRetryAfterHeaders(rateLimit);
  if (sessionState.reason === "expired" || sessionState.reason === "invalid") {
    headers.append("Set-Cookie", buildExpiredSessionCookie(runtime.config.oauth));
  }
  const csrf = ensureCsrfToken(cookieHeader);
  if (csrf.cookie) {
    headers.append("Set-Cookie", buildCsrfCookie(runtime.config.oauth, csrf.cookie));
  }

  return createHtmlResponse(
    renderAuthorizeHtml(client, {
      csrfToken: csrf.token,
      edTokenHint:
        canReuseAuthorizeSession(runtime, sessionState.session?.userId)
          ? "Leave this blank to reuse your current browser session."
          : "Paste your Ed API token here.",
      errorMessage: "Too many attempts. Wait a bit and try again.",
      params,
      requestedScopes: params.scopes,
      session: sessionState.reason === "valid" ? sessionState.session ?? undefined : undefined,
      showEdToken:
        sessionState.reason !== "valid" ||
        !canReuseAuthorizeSession(runtime, sessionState.session?.userId)
    }),
    429,
    headers
  );
}

function canReuseAuthorizeSession(runtime: Runtime, userId: number | undefined): boolean {
  if (!userId) {
    return false;
  }

  const status = runtime.credentials.getConnectionStatus(userId);
  return status.connected && !status.isInvalid;
}

function mapEdConnectionError(error: unknown): string {
  if (error instanceof EdIdentityMismatchError) {
    return `${error.message} Start a fresh OAuth sign-in if you want to switch accounts.`;
  }
  return error instanceof Error ? error.message : String(error);
}

function appendSessionCleanupCookies(
  headers: Headers,
  config: Runtime["config"]["oauth"],
  reason: "missing" | "expired" | "invalid"
): void {
  if (reason === "missing") {
    return;
  }

  headers.append("Set-Cookie", buildExpiredSessionCookie(config));
  headers.append("Set-Cookie", buildExpiredCsrfCookie(config));
}

function renderSessionRequiredPage(
  kind: "settings" | "reconnect",
  reason: "missing" | "expired" | "invalid"
): string {
  const detail =
    reason === "expired"
      ? "Your browser session expired. Start a fresh OAuth sign-in, then come back."
      : reason === "invalid"
        ? "Your browser session is no longer valid. Start a fresh OAuth sign-in, then come back."
        : "Open this page from a browser session that already authorized EdStem MCP.";
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>EdStem MCP</title></head>
  <body>
    <main>
      <h1>Sign in first</h1>
      <p>${escapeHtml(detail)}</p>
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

function escapeAttribute(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}
