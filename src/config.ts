const DEFAULT_API_BASE_URL = "https://edstem.org/api/";

function normalizeApiBaseUrl(value: string | undefined): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    return DEFAULT_API_BASE_URL;
  }
  return `${trimmed.replace(/\/+$/, "")}/`;
}

function parsePort(value: string | undefined): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return 8787;
  }
  return parsed;
}

export interface AppConfig {
  apiBaseUrl: string;
  edApiToken: string;
  mcpPath: string;
  port: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const edApiToken = env.ED_API_TOKEN?.trim();
  if (!edApiToken) {
    throw new Error("ED_API_TOKEN is required");
  }

  return {
    apiBaseUrl: normalizeApiBaseUrl(env.ED_API_BASE_URL),
    edApiToken,
    mcpPath: env.MCP_PATH?.trim() || "/mcp",
    port: parsePort(env.PORT)
  };
}
