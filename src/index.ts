import express from "express";

import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { loadConfig } from "./config.js";
import { createServer, mapToolError } from "./mcp/server.js";
import { EdstemOAuthProvider } from "./oauth/provider.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const app = createMcpExpressApp();
  const authProvider = config.oauth.enabled ? new EdstemOAuthProvider(config.oauth) : null;

  app.use(express.json({ limit: "1mb" }));

  if (authProvider) {
    app.use(
      mcpAuthRouter({
        issuerUrl: config.oauth.issuerUrl,
        provider: authProvider,
        resourceName: "EdStem MCP",
        resourceServerUrl: config.oauth.mcpServerUrl,
        scopesSupported: [config.oauth.scope]
      })
    );
  }

  const authMiddleware = authProvider
    ? requireBearerAuth({
        requiredScopes: [config.oauth.scope],
        resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(config.oauth.mcpServerUrl),
        verifier: authProvider
      })
    : null;

  app.all(config.mcpPath, ...(authMiddleware ? [authMiddleware] : []), async (request, response) => {
    const server = createServer(config);
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
      const mapped = mapToolError(error);
      if (!response.headersSent) {
        response.status(500).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: mapped.message
          },
          id: null
        });
      }
    }
  });

  app.get("/health", (_request, response) => {
    response.json({
      ok: true,
      service: "edstem-mcp"
    });
  });

  app.listen(config.port, () => {
    console.log(`edstem-mcp listening on http://localhost:${config.port}${config.mcpPath}`);
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
