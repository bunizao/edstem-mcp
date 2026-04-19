import { createServer } from "node:net";

import type { Runtime } from "../../src/runtime.js";
import { createApp } from "../../src/app.js";
import { EdstemOAuthProvider } from "../../src/oauth/provider.js";

export async function startAppServer(runtime: Runtime): Promise<{
  baseUrl: string;
  close: () => void;
}>;
export async function startAppServer(
  runtime: Runtime,
  options: { syncPublicBaseUrl: true }
): Promise<{
  baseUrl: string;
  close: () => void;
}>;
export async function startAppServer(
  runtime: Runtime,
  options?: { syncPublicBaseUrl: true }
): Promise<{
  baseUrl: string;
  close: () => void;
}> {
  const reservedPort = options?.syncPublicBaseUrl ? await reservePort() : 0;
  if (options?.syncPublicBaseUrl) {
    const baseUrl = `http://127.0.0.1:${reservedPort}`;
    runtime.config.port = reservedPort;
    runtime.config.publicBaseUrl = new URL(baseUrl);
    runtime.config.oauth.issuerUrl = new URL(baseUrl);
    runtime.config.oauth.mcpServerUrl = new URL(runtime.config.mcpPath, baseUrl);
    runtime.oauthProvider = new EdstemOAuthProvider({
      config: runtime.config,
      credentials: runtime.credentials,
      logger: runtime.logger,
      store: runtime.store,
      users: runtime.users
    });
  }

  const app = createApp(runtime);
  const server = Bun.serve({
    fetch: app.fetch,
    port: reservedPort
  });

  return {
    baseUrl: `http://127.0.0.1:${server.port}`,
    close: () => {
      server.stop(true);
    }
  };
}

async function reservePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const server = createServer();

    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Unable to reserve a test port."));
        return;
      }

      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(address.port);
      });
    });
  });
}
