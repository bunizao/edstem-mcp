import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export interface RenderAuthorizePageOptions {
  csrfToken: string;
  edTokenHint: string;
  errorMessage?: string;
  params: AuthorizationParams;
  requestedScopes: string[];
  session?: {
    displayName: string;
    email: string;
  };
  showEdToken: boolean;
}

export function renderAuthorizePage(
  client: OAuthClientInformationFull,
  options: RenderAuthorizePageOptions
): string {
  const clientName = client.client_name || client.client_id;
  const primaryAction = options.showEdToken ? "Continue" : "Continue with current session";
  const tokenPlaceholder = options.showEdToken
    ? "Paste your Ed API token"
    : "Leave blank to reuse this browser session";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize ${escapeHtml(clientName)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet">
    <style>
      :root {
        color-scheme: light;
        --background: #f6f3ee;
        --surface: rgba(255, 255, 255, 0.84);
        --surface-strong: #ffffff;
        --panel: #171717;
        --panel-muted: rgba(255, 255, 255, 0.72);
        --text: #171717;
        --muted: #66615a;
        --border: rgba(23, 23, 23, 0.1);
        --border-strong: rgba(255, 255, 255, 0.12);
        --accent: #1f6b57;
        --accent-hover: #184f42;
        --danger: #a13f35;
        --shadow: 0 30px 80px rgba(17, 17, 17, 0.12);
        --radius-xl: 28px;
        --radius-lg: 18px;
        --radius-md: 14px;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        background:
          radial-gradient(circle at top left, rgba(31, 107, 87, 0.14), transparent 30%),
          radial-gradient(circle at bottom right, rgba(23, 23, 23, 0.08), transparent 34%),
          linear-gradient(180deg, #fbf9f5 0%, var(--background) 100%);
        color: var(--text);
        font-family: "IBM Plex Sans", sans-serif;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background-image:
          linear-gradient(rgba(255, 255, 255, 0.12) 1px, transparent 1px),
          linear-gradient(90deg, rgba(255, 255, 255, 0.12) 1px, transparent 1px);
        background-size: 32px 32px;
        mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.2), transparent 75%);
      }
      .shell {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 2rem;
      }
      .auth-card {
        width: min(100%, 72rem);
        display: grid;
        grid-template-columns: minmax(18rem, 1fr) minmax(22rem, 30rem);
        border: 1px solid var(--border);
        border-radius: var(--radius-xl);
        overflow: hidden;
        background: color-mix(in srgb, var(--surface) 88%, white);
        box-shadow: var(--shadow);
        backdrop-filter: blur(24px);
        animation: fade-up 260ms ease-out both;
      }
      .intro {
        position: relative;
        padding: 2.5rem;
        background:
          radial-gradient(circle at top left, rgba(255, 255, 255, 0.12), transparent 30%),
          linear-gradient(160deg, #111111 0%, #1c1c1c 52%, #12372e 100%);
        color: white;
      }
      .intro::after {
        content: "";
        position: absolute;
        inset: auto 2.5rem 2rem 2.5rem;
        height: 1px;
        background: linear-gradient(90deg, rgba(255, 255, 255, 0.22), transparent);
      }
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        min-height: 2rem;
        padding: 0.3rem 0.75rem;
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.08);
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.02em;
      }
      .intro h1,
      .panel h2 {
        margin: 0;
        font-family: "Instrument Serif", serif;
        font-weight: 400;
        letter-spacing: -0.03em;
      }
      .intro h1 {
        margin-top: 1.5rem;
        font-size: clamp(2.5rem, 5vw, 4.2rem);
        line-height: 0.95;
        max-width: 10ch;
      }
      .intro p {
        margin: 1rem 0 0;
        max-width: 32rem;
        color: var(--panel-muted);
        font-size: 1rem;
        line-height: 1.65;
      }
      .feature-list {
        margin: 2rem 0 0;
        padding: 0;
        list-style: none;
        display: grid;
        gap: 1rem;
      }
      .feature-list li {
        display: grid;
        gap: 0.3rem;
        padding: 0.95rem 1rem;
        border: 1px solid var(--border-strong);
        border-radius: var(--radius-md);
        background: rgba(255, 255, 255, 0.06);
      }
      .feature-list strong {
        font-size: 0.95rem;
      }
      .feature-list span {
        color: rgba(255, 255, 255, 0.72);
        font-size: 0.9rem;
        line-height: 1.55;
      }
      .meta {
        margin-top: 2rem;
        display: grid;
        gap: 0.75rem;
        color: rgba(255, 255, 255, 0.72);
        font-size: 0.88rem;
      }
      .meta code {
        display: inline-block;
        max-width: 100%;
        overflow-wrap: anywhere;
        color: white;
        font-family: "IBM Plex Sans", sans-serif;
        font-size: 0.88rem;
      }
      .panel {
        padding: 2.25rem;
        background: color-mix(in srgb, var(--surface-strong) 96%, white);
      }
      .panel-header {
        display: grid;
        gap: 0.65rem;
      }
      .panel-header p {
        margin: 0;
        color: var(--muted);
        line-height: 1.6;
      }
      .panel h2 {
        font-size: clamp(2rem, 5vw, 2.9rem);
        line-height: 0.98;
      }
      .status,
      .error {
        margin-top: 1.25rem;
        padding: 1rem 1.05rem;
        border-radius: var(--radius-md);
        border: 1px solid var(--border);
      }
      .status {
        background: rgba(31, 107, 87, 0.06);
      }
      .status strong {
        display: block;
        font-size: 0.92rem;
      }
      .status span {
        display: block;
        margin-top: 0.3rem;
        color: var(--muted);
        font-size: 0.92rem;
      }
      .error {
        border-color: color-mix(in srgb, var(--danger) 22%, white);
        background: color-mix(in srgb, var(--danger) 9%, white);
        color: var(--danger);
      }
      form {
        margin-top: 1.5rem;
        display: grid;
        gap: 1rem;
      }
      .field {
        display: grid;
        gap: 0.45rem;
      }
      label {
        font-size: 0.92rem;
        font-weight: 600;
      }
      input[type="password"] {
        width: 100%;
        min-height: 3.1rem;
        border: 1px solid var(--border);
        border-radius: var(--radius-md);
        padding: 0.9rem 1rem;
        background: white;
        color: var(--text);
        font: inherit;
        transition: border-color 160ms ease, box-shadow 160ms ease;
      }
      input[type="password"]:focus {
        outline: none;
        border-color: color-mix(in srgb, var(--accent) 60%, white);
        box-shadow: 0 0 0 4px rgba(31, 107, 87, 0.12);
      }
      .hint,
      .token-link {
        margin: 0;
        color: var(--muted);
        font-size: 0.9rem;
        line-height: 1.55;
      }
      .token-link {
        text-decoration: none;
        width: fit-content;
      }
      .token-link:hover {
        color: var(--accent);
      }
      .scope-card {
        display: grid;
        gap: 0.9rem;
        padding: 1rem;
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        background: rgba(17, 17, 17, 0.025);
      }
      .scope {
        display: flex;
        gap: 0.75rem;
        align-items: flex-start;
      }
      .scope input {
        margin-top: 0.25rem;
      }
      .scope-copy {
        display: grid;
        gap: 0.25rem;
      }
      .scope-copy strong {
        font-size: 0.94rem;
      }
      .scope-copy span {
        color: var(--muted);
        font-size: 0.9rem;
        line-height: 1.5;
      }
      .submit {
        min-height: 3.1rem;
        border: 0;
        border-radius: var(--radius-md);
        background: var(--accent);
        color: white;
        font: inherit;
        font-weight: 600;
        cursor: pointer;
        transition: transform 160ms ease, background 160ms ease, box-shadow 160ms ease;
      }
      .submit:hover {
        background: var(--accent-hover);
        transform: translateY(-1px);
        box-shadow: 0 14px 30px rgba(31, 107, 87, 0.18);
      }
      .footnote {
        margin-top: 1.25rem;
        color: var(--muted);
        font-size: 0.88rem;
        line-height: 1.55;
      }
      @media (max-width: 900px) {
        .auth-card {
          grid-template-columns: 1fr;
        }
        .intro {
          padding-bottom: 2.25rem;
        }
      }
      @media (max-width: 640px) {
        .shell {
          padding: 1rem;
        }
        .intro,
        .panel {
          padding: 1.5rem;
        }
      }
      @keyframes fade-up {
        from {
          opacity: 0;
          transform: translateY(16px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }
    </style>
  </head>
  <body>
    <main class="shell">
      <div class="auth-card">
        <section class="intro">
          <div class="badge">EdStem MCP</div>
          <h1>Use Ed Discussion from any MCP client.</h1>
          <p>One Ed API token is enough. No local password wall. Read access is always required, and write access stays opt-in.</p>

          <ul class="feature-list">
            <li>
              <strong>Verified before storage</strong>
              <span>Your token is checked against Ed before this service keeps anything.</span>
            </li>
            <li>
              <strong>Single identity model</strong>
              <span>Your Ed account is your account here. No extra sign-up ceremony.</span>
            </li>
            <li>
              <strong>Write scope stays explicit</strong>
              <span>Grant submission tools only when you actually want them.</span>
            </li>
          </ul>

          <div class="meta">
            <div>Client</div>
            <code>${escapeHtml(clientName)}</code>
            <div>Requested scopes</div>
            <code>${escapeHtml(options.requestedScopes.join(" "))}</code>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div class="badge" style="color: var(--text); border-color: var(--border); background: rgba(17, 17, 17, 0.03);">Authorization</div>
            <h2>Connect your Ed account</h2>
            <p>This client wants access to your courses, lessons, threads, and activity through the public EdStem MCP service.</p>
          </div>

          ${options.session ? `
            <div class="status">
              <strong>Current browser session</strong>
              <span>${escapeHtml(options.session.displayName)} · ${escapeHtml(options.session.email)}</span>
            </div>
          ` : ""}
          ${options.errorMessage ? `<div class="error">${escapeHtml(options.errorMessage)}</div>` : ""}

          <form method="post" action="/authorize">
            <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
            <input type="hidden" name="redirect_uri" value="${escapeHtml(options.params.redirectUri)}">
            <input type="hidden" name="response_type" value="code">
            <input type="hidden" name="code_challenge" value="${escapeHtml(options.params.codeChallenge)}">
            <input type="hidden" name="code_challenge_method" value="S256">
            ${options.params.state ? `<input type="hidden" name="state" value="${escapeHtml(options.params.state)}">` : ""}
            ${options.params.scopes?.length ? `<input type="hidden" name="scope" value="${escapeHtml(options.params.scopes.join(" "))}">` : ""}
            ${options.params.resource ? `<input type="hidden" name="resource" value="${escapeHtml(options.params.resource.href)}">` : ""}
            <input type="hidden" name="csrf_token" value="${escapeHtml(options.csrfToken)}">
            <input type="hidden" name="scope_read" value="1">

            <div class="field">
              <label for="ed_token">Ed API token</label>
              <input
                id="ed_token"
                name="ed_token"
                type="password"
                autocomplete="off"
                placeholder="${escapeHtml(tokenPlaceholder)}"
                ${options.showEdToken ? "required" : ""}
              >
              <p class="hint">${escapeHtml(options.edTokenHint)}</p>
            </div>

            <a class="token-link" href="https://edstem.org/settings/api-tokens" target="_blank" rel="noreferrer">Open Ed API token settings</a>

            <div class="scope-card">
              <div class="scope">
                <input type="checkbox" checked disabled>
                <div class="scope-copy">
                  <strong>Read your Ed courses, lessons, threads, and activity</strong>
                  <span>Required for every MCP request.</span>
                </div>
              </div>
              ${options.requestedScopes.includes("mcp:tools.write") ? `
                <div class="scope">
                  <input id="scope_write" name="scope_write" type="checkbox" value="1">
                  <div class="scope-copy">
                    <label for="scope_write"><strong>Allow write tools</strong></label>
                    <span>Only enable this if you want to submit quiz answers or submit slides.</span>
                  </div>
                </div>
              ` : ""}
            </div>

            <button class="submit" type="submit">${escapeHtml(primaryAction)}</button>
          </form>

          <p class="footnote">No country code is needed. This service uses the same Ed API token flow as edstem-cli.</p>
        </section>
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
