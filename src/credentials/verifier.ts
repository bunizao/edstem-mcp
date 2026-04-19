const INVALID_TOKEN_MESSAGE =
  "Invalid or expired Ed API token. Regenerate it at https://edstem.org/settings/api-tokens.";

export interface VerifiedEdIdentity {
  edUserEmail: string;
  edUserId: number;
  edUserName: string;
}

export class EdTokenInvalidError extends Error {
  constructor(message: string = INVALID_TOKEN_MESSAGE) {
    super(message);
    this.name = "EdTokenInvalidError";
  }
}

export class EdApiBaseUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EdApiBaseUrlError";
  }
}

export class EdApiUpstreamError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EdApiUpstreamError";
  }
}

export async function verifyEdToken(
  token: string,
  apiBaseUrl: string
): Promise<VerifiedEdIdentity> {
  const url = new URL("user", apiBaseUrl);

  let response: Response;
  try {
    response = await fetch(url, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`
      },
      redirect: "manual"
    });
  } catch (error) {
    throw new EdApiUpstreamError(`Failed to reach the Ed API: ${String(error)}`);
  }

  const payload = await parseJson(response);
  const code = asString(payload.code);
  const message = asString(payload.message);

  if (response.status === 400 || response.status === 401 || response.status === 403) {
    if (code === "bad_token" || response.status === 401 || response.status === 403) {
      throw new EdTokenInvalidError();
    }
    throw new EdApiUpstreamError(formatApiError(response.status, message));
  }

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location") ?? "an unknown location";
    throw new EdApiBaseUrlError(
      `Ed API base URL redirected to ${location}. Set ED_API_BASE_URL to a valid JSON API endpoint.`
    );
  }

  if (!response.ok) {
    throw new EdApiUpstreamError(formatApiError(response.status, message));
  }

  const user = asRecord(payload.user ?? payload);
  return {
    edUserId: asInt(user.id),
    edUserEmail: asString(user.email),
    edUserName: asString(user.name)
  };
}

async function parseJson(response: Response): Promise<Record<string, unknown>> {
  try {
    return asRecord(await response.json());
  } catch {
    throw new EdApiBaseUrlError(
      "Ed API returned a non-JSON response. Set ED_API_BASE_URL to a valid JSON API endpoint."
    );
  }
}

function asInt(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : Number.parseInt(String(value ?? 0), 10) || 0;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function formatApiError(statusCode: number, message: string): string {
  return message
    ? `Ed API error (HTTP ${statusCode}): ${message}`
    : `Ed API error (HTTP ${statusCode})`;
}
