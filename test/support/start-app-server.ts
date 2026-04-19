import type { Runtime } from "../../src/runtime.js";
import { createApp } from "../../src/app.js";

export async function startAppServer(runtime: Runtime): Promise<{
  baseUrl: string;
  close: () => void;
}> {
  const app = createApp(runtime);
  const server = Bun.serve({
    fetch: app.fetch,
    port: 0
  });

  return {
    baseUrl: `http://127.0.0.1:${server.port}`,
    close: () => {
      server.stop(true);
    }
  };
}
