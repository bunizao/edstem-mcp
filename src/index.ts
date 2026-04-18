import { loadConfig } from "./config.js";
import { createApp } from "./app.js";
import { createRuntime } from "./runtime.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const runtime = createRuntime(config);
  const app = createApp(runtime);
  const server = app.listen(config.port, () => {
    runtime.logger.info({
      mcpPath: config.mcpPath,
      port: config.port
    }, "edstem-mcp listening");
  });

  const shutdown = (signal: string) => {
    runtime.logger.info({ signal }, "shutting down");
    server.close((error) => {
      if (error) {
        runtime.logger.error({ error }, "failed to close server cleanly");
        process.exitCode = 1;
      }
      runtime.close();
    });
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
