import { randomUUID } from "node:crypto";

import express from "express";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthRouter
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { rateLimit } from "express-rate-limit";

import { createServer } from "./mcp/server.js";
import type { Runtime } from "./runtime.js";
import {
  buildExpiredCsrfCookie,
  buildCsrfCookie,
  ensureCsrfToken,
  validateCsrfToken
} from "./oauth/csrf.js";
import {
  buildExpiredSessionCookie,
  readSessionFromCookieHeader
} from "./oauth/session.js";

const authPageLimiter = rateLimit({
  limit: 20,
  standardHeaders: true,
  windowMs: 15 * 60 * 1000
});

export function createApp(runtime: Runtime): express.Express {
  const { config, credentials, oauthProvider, users, logger } = runtime;
  const app = express();

  app.set("trust proxy", 1);
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: false }));
  app.use(requestLogger(logger));

  if (config.oauth.enabled) {
    app.use(
      mcpAuthRouter({
        issuerUrl: config.oauth.issuerUrl,
        provider: oauthProvider,
        resourceName: "EdStem MCP",
        resourceServerUrl: config.oauth.mcpServerUrl,
        scopesSupported: config.oauth.supportedScopes
      })
    );
  }

  app.get("/healthz", (_request, response) => {
    response.json({ ok: true, service: "edstem-mcp" });
  });

  app.get("/readyz", (_request, response) => {
    response.json({
      db: true,
      key: Boolean(config.masterKey.length === 32),
      ok: true
    });
  });

  app.get("/settings", authPageLimiter, (request, response) => {
    const session = readSessionFromCookieHeader(request.headers.cookie, config.oauth);
    const csrf = ensureCsrfToken(request.headers.cookie);
    if (csrf.cookie) {
      response.setHeader("Set-Cookie", buildCsrfCookie(config.oauth, csrf.cookie));
    }

    if (!session) {
      response.status(401).type("html").send(renderSessionRequiredPage("settings"));
      return;
    }

    const status = credentials.getConnectionStatus(session.userId);
    response.type("html").send(
      renderSettingsPage({
        csrfToken: csrf.token,
        session,
        status
      })
    );
  });

  app.post("/settings/rotate", authPageLimiter, async (request, response) => {
    const session = readSessionFromCookieHeader(request.headers.cookie, config.oauth);
    const csrf = ensureCsrfToken(request.headers.cookie);
    if (csrf.cookie) {
      response.setHeader("Set-Cookie", buildCsrfCookie(config.oauth, csrf.cookie));
    }

    if (!session) {
      response.status(401).type("html").send(renderSessionRequiredPage("settings"));
      return;
    }
    if (!validateCsrfToken(request.headers.cookie, getFormField(request.body.csrf_token))) {
      response.status(403).type("html").send(renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: "Your session expired. Reload the page and try again.",
        session,
        status: credentials.getConnectionStatus(session.userId)
      }));
      return;
    }

    const edToken = getFormField(request.body.ed_token);
    if (!edToken) {
      response.status(422).type("html").send(
        renderSettingsPage({
          csrfToken: csrf.token,
          errorMessage: "Ed API token is required.",
          session,
          status: credentials.getConnectionStatus(session.userId)
        })
      );
      return;
    }

    try {
      await credentials.connect(session.userId, edToken);
      response.redirect("/settings");
    } catch (error) {
      response.status(422).type("html").send(
        renderSettingsPage({
          csrfToken: csrf.token,
          errorMessage: error instanceof Error ? error.message : String(error),
          session,
          status: credentials.getConnectionStatus(session.userId)
        })
      );
    }
  });

  app.post("/settings/delete", authPageLimiter, (request, response) => {
    const session = readSessionFromCookieHeader(request.headers.cookie, config.oauth);
    const csrf = ensureCsrfToken(request.headers.cookie);
    if (csrf.cookie) {
      response.setHeader("Set-Cookie", buildCsrfCookie(config.oauth, csrf.cookie));
    }

    if (!session) {
      response.status(401).type("html").send(renderSessionRequiredPage("settings"));
      return;
    }
    if (!validateCsrfToken(request.headers.cookie, getFormField(request.body.csrf_token))) {
      response.status(403).type("html").send(renderSettingsPage({
        csrfToken: csrf.token,
        errorMessage: "Your session expired. Reload the page and try again.",
        session,
        status: credentials.getConnectionStatus(session.userId)
      }));
      return;
    }

    credentials.delete(session.userId);
    users.deleteAccount(session.userId);
    response
      .setHeader("Set-Cookie", [
        buildExpiredSessionCookie(config.oauth),
        buildExpiredCsrfCookie(config.oauth)
      ])
      .type("html")
      .send(renderDeletedPage());
  });

  app.get("/reconnect", authPageLimiter, (request, response) => {
    const session = readSessionFromCookieHeader(request.headers.cookie, config.oauth);
    const csrf = ensureCsrfToken(request.headers.cookie);
    if (csrf.cookie) {
      response.setHeader("Set-Cookie", buildCsrfCookie(config.oauth, csrf.cookie));
    }

    if (!session) {
      response.status(401).type("html").send(renderSessionRequiredPage("reconnect"));
      return;
    }

    const status = credentials.getConnectionStatus(session.userId);
    response.type("html").send(
      renderReconnectPage({
        csrfToken: csrf.token,
        session,
        status
      })
    );
  });

  app.post("/reconnect", authPageLimiter, async (request, response) => {
    const session = readSessionFromCookieHeader(request.headers.cookie, config.oauth);
    const csrf = ensureCsrfToken(request.headers.cookie);
    if (csrf.cookie) {
      response.setHeader("Set-Cookie", buildCsrfCookie(config.oauth, csrf.cookie));
    }

    if (!session) {
      response.status(401).type("html").send(renderSessionRequiredPage("reconnect"));
      return;
    }
    if (!validateCsrfToken(request.headers.cookie, getFormField(request.body.csrf_token))) {
      response.status(403).type("html").send(renderReconnectPage({
        csrfToken: csrf.token,
        errorMessage: "Your session expired. Reload the page and try again.",
        session,
        status: credentials.getConnectionStatus(session.userId)
      }));
      return;
    }

    const edToken = getFormField(request.body.ed_token);
    if (!edToken) {
      response.status(422).type("html").send(
        renderReconnectPage({
          csrfToken: csrf.token,
          errorMessage: "Ed API token is required.",
          session,
          status: credentials.getConnectionStatus(session.userId)
        })
      );
      return;
    }

    try {
      await credentials.connect(session.userId, edToken);
      response.redirect("/settings");
    } catch (error) {
      response.status(422).type("html").send(
        renderReconnectPage({
          csrfToken: csrf.token,
          errorMessage: error instanceof Error ? error.message : String(error),
          session,
          status: credentials.getConnectionStatus(session.userId)
        })
      );
    }
  });

  const mcpLimiter = rateLimit({
    keyGenerator: (request) => String(request.auth?.extra?.userId ?? request.ip),
    limit: 60,
    standardHeaders: true,
    windowMs: 60 * 1000
  });

  app.all(
    config.mcpPath,
    config.oauth.enabled
      ? requireBearerAuth({
          requiredScopes: [config.oauth.readScope],
          resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(config.oauth.mcpServerUrl),
          verifier: oauthProvider
        })
      : (_request, _response, next) => next(),
    mcpLimiter,
    async (request, response) => {
      const server = createServer(config, credentials);
      const transport = new StreamableHTTPServerTransport({
        enableJsonResponse: true,
        sessionIdGenerator: undefined
      });

      try {
        await server.connect(transport);
        await transport.handleRequest(request, response, request.body);
        response.on("close", () => {
          void transport.close();
          void server.close();
        });
      } catch (error) {
        if (!response.headersSent) {
          response.status(500).json({
            error: {
              message: error instanceof Error ? error.message : String(error)
            },
            id: null,
            jsonrpc: "2.0"
          });
        }
      }
    }
  );

  return app;
}

function getFormField(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function requestLogger(logger: Runtime["logger"]) {
  return (request: express.Request, response: express.Response, next: express.NextFunction) => {
    const requestId = randomUUID();
    const startedAt = Date.now();
    response.setHeader("x-request-id", requestId);
    response.on("finish", () => {
      logger.info({
        durationMs: Date.now() - startedAt,
        method: request.method,
        requestId,
        statusCode: response.statusCode,
        url: request.originalUrl,
        userId: getUserId(request)
      });
    });
    next();
  };
}

function getUserId(request: express.Request): number | undefined {
  const userId = request.auth?.extra?.userId;
  return typeof userId === "number" ? userId : undefined;
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
