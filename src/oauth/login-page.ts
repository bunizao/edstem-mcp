import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export function renderLoginPage(options: {
  client: OAuthClientInformationFull;
  errorMessage?: string;
  params: AuthorizationParams;
  username?: string;
}): string {
  const { client, errorMessage, params, username } = options;
  const clientName = client.client_name || client.client_id;

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize ${escapeHtml(clientName)}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f3efe7;
        --panel: #fffaf3;
        --text: #1d1c1a;
        --muted: #665f53;
        --border: #d9cdb7;
        --accent: #165d52;
        --accent-text: #f7f3eb;
        --danger: #9f3124;
      }

      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background:
          radial-gradient(circle at top left, rgba(22, 93, 82, 0.12), transparent 34%),
          radial-gradient(circle at bottom right, rgba(159, 49, 36, 0.1), transparent 28%),
          var(--bg);
        color: var(--text);
        font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Palatino, serif;
      }
      main {
        width: min(100%, 28rem);
        margin: 2rem;
        padding: 2rem;
        border: 1px solid var(--border);
        border-radius: 20px;
        background: color-mix(in srgb, var(--panel) 92%, white);
        box-shadow: 0 20px 60px rgba(29, 28, 26, 0.08);
      }
      h1 {
        margin: 0 0 0.5rem;
        font-size: 2rem;
        line-height: 1.1;
      }
      p {
        margin: 0 0 1rem;
        color: var(--muted);
      }
      .error {
        margin: 1rem 0;
        padding: 0.75rem 0.9rem;
        border-radius: 12px;
        border: 1px solid color-mix(in srgb, var(--danger) 35%, white);
        background: color-mix(in srgb, var(--danger) 8%, white);
        color: var(--danger);
      }
      label {
        display: block;
        margin: 1rem 0 0.35rem;
        font-size: 0.95rem;
        font-weight: 600;
      }
      input {
        width: 100%;
        padding: 0.85rem 0.9rem;
        border-radius: 12px;
        border: 1px solid var(--border);
        font: inherit;
        background: white;
      }
      button {
        width: 100%;
        margin-top: 1.25rem;
        border: 0;
        border-radius: 12px;
        padding: 0.9rem 1rem;
        background: var(--accent);
        color: var(--accent-text);
        font: inherit;
        font-weight: 700;
        cursor: pointer;
      }
      .meta {
        margin-top: 1.5rem;
        padding-top: 1rem;
        border-top: 1px solid var(--border);
        font-size: 0.9rem;
      }
      code {
        font-family: "SF Mono", "Monaco", monospace;
        font-size: 0.85em;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Authorize ${escapeHtml(clientName)}</h1>
      <p>This connector is asking for access to the EdStem MCP tools.</p>
      ${errorMessage ? `<div class="error">${escapeHtml(errorMessage)}</div>` : ""}
      <form method="post" action="/authorize">
        <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
        <input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
        <input type="hidden" name="response_type" value="code">
        <input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
        <input type="hidden" name="code_challenge_method" value="S256">
        ${params.state ? `<input type="hidden" name="state" value="${escapeHtml(params.state)}">` : ""}
        ${params.scopes?.length ? `<input type="hidden" name="scope" value="${escapeHtml(params.scopes.join(" "))}">` : ""}
        ${params.resource ? `<input type="hidden" name="resource" value="${escapeHtml(params.resource.href)}">` : ""}

        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username" required value="${escapeHtml(username || "")}">

        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>

        <button type="submit">Continue</button>
      </form>

      <div class="meta">
        <p><strong>Client:</strong> <code>${escapeHtml(client.client_id)}</code></p>
        <p><strong>Requested scope:</strong> <code>${escapeHtml((params.scopes || []).join(" ") || "mcp:tools")}</code></p>
      </div>
    </main>
  </body>
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
