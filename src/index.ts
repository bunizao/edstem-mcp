import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { createRuntime } from "./runtime.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const runtime = createRuntime(config);
  const app = createApp(runtime);
  const server = Bun.serve({
    fetch: app.fetch,
    port: config.port
  });
  let isShuttingDown = false;

  runtime.logger.info(
    {
      hostname: server.hostname,
      mcpPath: config.mcpPath,
      port: server.port
    },
    "edstem-mcp listening"
  );

  const shutdown = (signal: string) => {
    if (isShuttingDown) {
      return;
    }
    isShuttingDown = true;
    runtime.logger.info({ signal }, "shutting down");
    server.stop(true);
    runtime.close();
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
