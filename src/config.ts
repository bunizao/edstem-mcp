const DEFAULT_API_BASE_URL = "https://edstem.org/api/";
const DEFAULT_OAUTH_STORE_PATH = ".data/oauth-store.json";

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

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value == null || value.trim() === "") {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
}

function normalizePath(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    return fallback;
  }
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function parseUrl(value: string | undefined, fallback: string): URL {
  const candidate = value?.trim() || fallback;
  return new URL(candidate);
}

export interface OAuthUserConfig {
  displayName: string;
  id: string;
  password: string;
  username: string;
}

export interface OAuthConfig {
  accessTokenTtlSeconds: number;
  enabled: boolean;
  issuerUrl: URL;
  mcpServerUrl: URL;
  refreshTokenTtlSeconds: number;
  scope: string;
  sessionCookieName: string;
  sessionSecret: string;
  sessionTtlSeconds: number;
  storePath: string;
  user: OAuthUserConfig;
}

export interface AppConfig {
  apiBaseUrl: string;
  edApiToken: string;
  mcpPath: string;
  oauth: OAuthConfig;
  port: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const edApiToken = env.ED_API_TOKEN?.trim();
  if (!edApiToken) {
    throw new Error("ED_API_TOKEN is required");
  }

  const port = parsePort(env.PORT);
  const mcpPath = normalizePath(env.MCP_PATH, "/mcp");
  const oauthEnabled = parseBoolean(env.OAUTH_ENABLED, true);
  const publicBaseUrl = parseUrl(env.PUBLIC_BASE_URL, `http://localhost:${port}`);
  const issuerUrl = parseUrl(env.OAUTH_ISSUER_URL, publicBaseUrl.href);
  const sessionSecret = env.OAUTH_SESSION_SECRET?.trim() || "dev-session-secret-change-me";
  const username = env.OAUTH_USERNAME?.trim() || "admin";
  const password = env.OAUTH_PASSWORD?.trim() || "dev-password-change-me";

  return {
    apiBaseUrl: normalizeApiBaseUrl(env.ED_API_BASE_URL),
    edApiToken,
    mcpPath,
    oauth: {
      accessTokenTtlSeconds: parsePositiveInt(env.OAUTH_ACCESS_TOKEN_TTL_SECONDS, 3600),
      enabled: oauthEnabled,
      issuerUrl,
      mcpServerUrl: new URL(mcpPath, publicBaseUrl),
      refreshTokenTtlSeconds: parsePositiveInt(env.OAUTH_REFRESH_TOKEN_TTL_SECONDS, 2592000),
      scope: "mcp:tools",
      sessionCookieName: env.OAUTH_SESSION_COOKIE_NAME?.trim() || "edstem_mcp_session",
      sessionSecret,
      sessionTtlSeconds: parsePositiveInt(env.OAUTH_SESSION_TTL_SECONDS, 604800),
      storePath: env.OAUTH_STORE_PATH?.trim() || DEFAULT_OAUTH_STORE_PATH,
      user: {
        displayName: env.OAUTH_USER_DISPLAY_NAME?.trim() || "EdStem MCP User",
        id: env.OAUTH_USER_ID?.trim() || username,
        password,
        username
      }
    },
    port
  };
}
