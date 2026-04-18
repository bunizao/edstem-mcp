import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export interface RenderAuthorizePageOptions {
  csrfToken: string;
  edTokenHint: string;
  errorMessage?: string;
  params: AuthorizationParams;
  requestedScopes: string[];
  selectedTab: "signin" | "signup";
  session?: {
    displayName: string;
    email: string;
  };
  showEdToken: boolean;
  signInEmail?: string;
  signUpDisplayName?: string;
  signUpEmail?: string;
}

export function renderAuthorizePage(
  client: OAuthClientInformationFull,
  options: RenderAuthorizePageOptions
): string {
  const clientName = client.client_name || client.client_id;
  const sessionLabel = options.session
    ? `${options.session.displayName} <${options.session.email}>`
    : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize ${escapeHtml(clientName)}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f4efe5;
        --panel: #fffaf1;
        --text: #1e1b16;
        --muted: #6a6255;
        --border: #d9c8aa;
        --accent: #145a52;
        --accent-2: #8d4b25;
        --danger: #a53d2b;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background:
          radial-gradient(circle at top left, rgba(20, 90, 82, 0.12), transparent 32%),
          radial-gradient(circle at bottom right, rgba(141, 75, 37, 0.14), transparent 30%),
          var(--bg);
        color: var(--text);
        font-family: "Iowan Old Style", "Palatino Linotype", Palatino, serif;
      }
      main {
        width: min(100%, 34rem);
        margin: 2rem;
        padding: 2rem;
        border: 1px solid var(--border);
        border-radius: 24px;
        background: color-mix(in srgb, var(--panel) 94%, white);
        box-shadow: 0 20px 60px rgba(31, 28, 23, 0.12);
      }
      h1 {
        margin: 0 0 0.4rem;
        font-size: 2rem;
        line-height: 1.05;
      }
      p {
        margin: 0 0 1rem;
        color: var(--muted);
      }
      .pill {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        margin: 0.35rem 0 1rem;
        padding: 0.35rem 0.65rem;
        border: 1px solid var(--border);
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.6);
        font-size: 0.9rem;
      }
      .error {
        margin: 1rem 0;
        padding: 0.85rem 0.95rem;
        border-radius: 14px;
        border: 1px solid color-mix(in srgb, var(--danger) 35%, white);
        background: color-mix(in srgb, var(--danger) 8%, white);
        color: var(--danger);
      }
      .tabs {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.5rem;
        margin: 1rem 0;
      }
      .tab {
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 0.75rem 1rem;
        background: white;
        color: var(--muted);
        cursor: pointer;
        font: inherit;
        font-weight: 700;
      }
      .tab[aria-pressed="true"] {
        border-color: var(--accent);
        color: var(--accent);
      }
      .section {
        display: grid;
        gap: 0.25rem;
        margin-top: 1rem;
      }
      .field {
        display: grid;
        gap: 0.35rem;
      }
      label {
        font-size: 0.95rem;
        font-weight: 700;
      }
      input[type="text"],
      input[type="email"],
      input[type="password"] {
        width: 100%;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 0.85rem 0.95rem;
        font: inherit;
        background: white;
      }
      .hint {
        margin: 0;
        font-size: 0.88rem;
        color: var(--muted);
      }
      .scopes {
        display: grid;
        gap: 0.75rem;
        margin-top: 1rem;
        padding: 1rem;
        border: 1px solid var(--border);
        border-radius: 16px;
        background: rgba(255, 255, 255, 0.55);
      }
      .scope {
        display: flex;
        gap: 0.75rem;
        align-items: flex-start;
      }
      .scope input {
        margin-top: 0.25rem;
      }
      button[type="submit"] {
        width: 100%;
        margin-top: 1.25rem;
        border: 0;
        border-radius: 14px;
        padding: 0.95rem 1rem;
        background: var(--accent);
        color: white;
        font: inherit;
        font-weight: 800;
        cursor: pointer;
      }
      .meta {
        margin-top: 1.5rem;
        padding-top: 1rem;
        border-top: 1px solid var(--border);
        font-size: 0.9rem;
        color: var(--muted);
      }
      .meta strong {
        color: var(--text);
      }
      .pane[hidden] {
        display: none !important;
      }
      code {
        font-family: "SFMono-Regular", "SF Mono", Monaco, monospace;
        font-size: 0.88em;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Connect EdStem MCP</h1>
      <p>This connector wants access to your EdStem account.</p>
      ${options.session ? `<div class="pill">Signed in as ${escapeHtml(sessionLabel)}</div>` : ""}
      ${options.errorMessage ? `<div class="error">${escapeHtml(options.errorMessage)}</div>` : ""}
      <form method="post" action="/authorize" id="auth-form">
        <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
        <input type="hidden" name="redirect_uri" value="${escapeHtml(options.params.redirectUri)}">
        <input type="hidden" name="response_type" value="code">
        <input type="hidden" name="code_challenge" value="${escapeHtml(options.params.codeChallenge)}">
        <input type="hidden" name="code_challenge_method" value="S256">
        ${options.params.state ? `<input type="hidden" name="state" value="${escapeHtml(options.params.state)}">` : ""}
        ${options.params.scopes?.length ? `<input type="hidden" name="scope" value="${escapeHtml(options.params.scopes.join(" "))}">` : ""}
        ${options.params.resource ? `<input type="hidden" name="resource" value="${escapeHtml(options.params.resource.href)}">` : ""}
        <input type="hidden" name="csrf_token" value="${escapeHtml(options.csrfToken)}">
        <input type="hidden" name="tab" id="tab-input" value="${escapeHtml(options.selectedTab)}">

        <div class="tabs" role="tablist" aria-label="Account mode">
          <button type="button" class="tab" data-tab="signin" aria-pressed="${options.selectedTab === "signin"}">Sign in</button>
          <button type="button" class="tab" data-tab="signup" aria-pressed="${options.selectedTab === "signup"}">Sign up</button>
        </div>

        <section class="pane" data-pane="signin" ${options.selectedTab === "signin" ? "" : "hidden"}>
          <div class="section">
            <div class="field">
              <label for="signin_email">Email</label>
              <input id="signin_email" name="signin_email" type="email" autocomplete="username" required value="${escapeHtml(options.signInEmail ?? options.session?.email ?? "")}">
            </div>
            <div class="field">
              <label for="signin_password">Password</label>
              <input id="signin_password" name="signin_password" type="password" autocomplete="current-password">
            </div>
          </div>
        </section>

        <section class="pane" data-pane="signup" ${options.selectedTab === "signup" ? "" : "hidden"}>
          <div class="section">
            <div class="field">
              <label for="signup_display_name">Display name</label>
              <input id="signup_display_name" name="signup_display_name" type="text" autocomplete="name" value="${escapeHtml(options.signUpDisplayName ?? options.session?.displayName ?? "")}">
            </div>
            <div class="field">
              <label for="signup_email">Email</label>
              <input id="signup_email" name="signup_email" type="email" autocomplete="email" value="${escapeHtml(options.signUpEmail ?? options.session?.email ?? "")}">
            </div>
            <div class="field">
              <label for="signup_password">Password</label>
              <input id="signup_password" name="signup_password" type="password" autocomplete="new-password">
            </div>
            <div class="field">
              <label for="signup_confirm_password">Confirm password</label>
              <input id="signup_confirm_password" name="signup_confirm_password" type="password" autocomplete="new-password">
            </div>
          </div>
        </section>

        <div class="section" style="margin-top: 1rem;">
          <div class="field">
            <label for="ed_token">Ed API token</label>
            <input id="ed_token" name="ed_token" type="password" autocomplete="off" ${options.showEdToken ? "required" : ""}>
            <p class="hint">${escapeHtml(options.edTokenHint)}</p>
          </div>
        </div>

        <div class="scopes">
          <div class="scope">
            <input type="checkbox" checked disabled>
            <div>
              <strong>Read your Ed courses, lessons, threads, and activity</strong>
              <p class="hint">Required for all MCP tool access.</p>
            </div>
          </div>
          <input type="hidden" name="scope_read" value="1">
          ${options.requestedScopes.includes("mcp:tools.write") ? `
            <div class="scope">
              <input id="scope_write" name="scope_write" type="checkbox" value="1">
              <div>
                <label for="scope_write"><strong>Submit quiz answers and slides</strong></label>
                <p class="hint">Optional. Only grant this if you want write tools.</p>
              </div>
            </div>
          ` : ""}
        </div>

        <button type="submit">Continue</button>
      </form>

      <div class="meta">
        <p><strong>Client:</strong> <code>${escapeHtml(client.client_id)}</code></p>
        <p><strong>Requested scopes:</strong> <code>${escapeHtml(options.requestedScopes.join(" "))}</code></p>
      </div>
    </main>
    <script>
      const form = document.getElementById('auth-form');
      const tabInput = document.getElementById('tab-input');
      const panes = Array.from(document.querySelectorAll('[data-pane]'));
      const buttons = Array.from(document.querySelectorAll('[data-tab]'));
      const edTokenRequired = ${options.showEdToken ? "true" : "false"};
      const sync = () => {
        const tab = tabInput.value;
        buttons.forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.tab === tab)));
        panes.forEach((pane) => {
          pane.hidden = pane.dataset.pane !== tab;
          pane.querySelectorAll('input').forEach((input) => {
            if (input.name === 'ed_token' || input.name === 'signin_password' || input.name === 'signup_password' || input.name === 'signup_confirm_password' || input.name === 'signin_email' || input.name === 'signup_email' || input.name === 'signup_display_name') {
              const required = input.name === 'signin_email' && tab === 'signin'
                || input.name === 'signin_password' && tab === 'signin'
                || input.name === 'signup_email' && tab === 'signup'
                || input.name === 'signup_password' && tab === 'signup'
                || input.name === 'signup_confirm_password' && tab === 'signup'
                || input.name === 'ed_token' && edTokenRequired;
              input.required = required;
            }
          });
        });
      };
      buttons.forEach((button) => {
        button.addEventListener('click', () => {
          tabInput.value = button.dataset.tab;
          sync();
        });
      });
      sync();
    </script>
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
