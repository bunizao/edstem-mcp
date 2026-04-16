import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { loadConfig } from "./config.js";
import { createServer, mapToolError } from "./mcp/server.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const app = createMcpExpressApp();

  app.all(config.mcpPath, async (request, response) => {
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
