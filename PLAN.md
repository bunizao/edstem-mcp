# edstem-mcp Implementation Plan

> A remote MCP server that lets any MCP-compatible client (claude.ai, Cursor, Claude Desktop, custom) call EdStem tools using the user's own Ed Discussion API token.

Version: v2 (2026-04-18)
Status: For review
Scope intent: **secure and simple**. No email verification. No billing. No multi-tenant SaaS infrastructure. A small, self-hosted server that 1–100 people can use safely.

---

## 0. Conventions

- All paths are relative to the `edstem-mcp/` repo root.
- `Decision ▸` markers call out questions that still need a human call. The doc gives a recommendation but does not assume.
- `[ ]` items are milestone checklist entries to be ticked off during implementation.
- All source code, comments, and commit messages are in English.

---

## 1. Background and Goals

### 1.1 Current state

| Area | Status | Notes |
|---|---|---|
| Protocol layer | Streamable HTTP MCP transport mounted at `/mcp` (`src/index.ts`) | OK |
| Auth layer | OAuth 2.1 + PKCE wired via `mcpAuthRouter` + `requireBearerAuth` | Framework OK, but only one hardcoded admin user |
| OAuth storage | `FileOAuthStore` writes JSON with an in-memory write queue (`src/oauth/store.ts`) | Single-instance OK; will lose writes under multi-process |
| Ed client | `EdClient` accepts a token, implements 10 read-only endpoints (`src/ed/client.ts`) | Works, but token comes from a global `ED_API_TOKEN` |
| Tool surface | 10 read-only tools (`src/mcp/server.ts`) | Missing the write operations the CLI already supports (quiz answer / submit) |
| Per-user isolation | **None** — every OAuth user shares the server's single Ed token | This is the core problem this plan solves |

### 1.2 Target state

1. Anyone can connect from claude.ai (Add Connector) or any MCP client.
2. Each user supplies and uses **their own** Ed API token. Zero cross-user visibility.
3. Ed tokens are encrypted at rest and survive server restarts.
4. The MCP tool surface matches `edstem-cli` (including write operations, gated by an explicit OAuth scope).
5. A single instance comfortably serves up to ~100 concurrent users.

### 1.3 Non-goals

- High availability, multi-region, failover.
- Browser extensions, mobile SDKs.
- Data sources other than EdStem.
- Team / org accounts, shared credentials.
- Email verification, password reset email flows, SMTP.
- Billing, paid tiers, usage metering.
- SAML / SSO for school IdPs.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Clients                                                     │
│  - claude.ai connector                                       │
│  - Cursor (mcp.json)                                         │
│  - Claude Desktop                                            │
│  - Custom CLI / SDK                                          │
└────────────────────────────┬─────────────────────────────────┘
                             │ OAuth 2.1 + PKCE
                             │ MCP Streamable HTTP
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Reverse Proxy (Caddy / nginx)                               │
│  - TLS termination                                           │
│  - Coarse global rate limit                                  │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTPS
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  Express App (src/index.ts)                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ mcpAuthRouter                                          │  │
│  │  - /.well-known/oauth-protected-resource               │  │
│  │  - /.well-known/oauth-authorization-server             │  │
│  │  - /authorize  (POST single-screen form)               │  │
│  │  - /token /register /revoke                            │  │
│  │   provider = EdstemOAuthProvider                       │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ /settings  /reconnect   (small HTML utility pages)     │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ /mcp  -- requireBearerAuth --> tool dispatcher         │  │
│  │   per-request EdClient (with this user's Ed token)     │  │
│  └────────────────────────────────────────────────────────┘  │
└────────────────────────────┬─────────────────────────────────┘
                             │ user_id -> DB lookup ed_credentials
                             ▼
┌──────────────────────────────────────────────────────────────┐
│  SQLite (better-sqlite3, WAL mode)                           │
│  Tables: users, ed_credentials, oauth_*                      │
└──────────────────────────────────────────────────────────────┘
                             │ Bearer <ed_token>
                             ▼
                    https://edstem.org/api
```

SQLite is the only datastore for the lifetime of this plan. With WAL mode and a single Express process it comfortably handles the target load. If the project ever outgrows it, the storage layer is intentionally driver-agnostic so a Postgres swap is a localized change.

---

## 3. Authentication Design (Option B: single-screen)

### 3.1 User journey

**First-time connection** (claude.ai perspective):

1. User visits claude.ai → Settings → Connectors → Add → enters `https://your-mcp-host`.
2. claude.ai discovers `/.well-known/oauth-protected-resource` and learns OAuth is required.
3. claude.ai performs Dynamic Client Registration via POST `/register`, obtains a `client_id`.
4. Browser is redirected to `/authorize?response_type=code&client_id=...&code_challenge=...&redirect_uri=...`.
5. The server renders the **single-screen form** (see §3.2).
6. User submits the form. The server:
   - Validates email/password (sign-in) or creates a new account (sign-up).
   - Calls `GET edstem.org/api/user` to verify the Ed token.
   - Encrypts the Ed token (AES-256-GCM) and persists it in `ed_credentials`.
   - Issues an authorization code, redirects back to claude.ai.
7. claude.ai exchanges the code for an access + refresh token via `/token`.
8. On every subsequent tool call: claude.ai sends the bearer token → server resolves the user → fetches their Ed token → calls Ed.

**Returning user**:

1. Steps 1–5 are identical, but the user picks the "Sign in" tab and only fills email + password.
2. If the user's `ed_credentials` row is present and not flagged invalid, the server skips Ed token re-entry.
3. If it is missing or flagged invalid, the form re-displays the Ed token field for re-entry.

### 3.2 Single-screen UI sketch

```
┌────────────────────────────────────────────────────────┐
│  Connect EdStem MCP                                    │
│                                                        │
│  [ Sign in ]  [ Sign up ]                              │
│  ─────────                                             │
│                                                        │
│  Email           [_______________________________]     │
│  Password        [_______________________________]     │
│  (Sign up only)                                        │
│  Confirm pwd     [_______________________________]     │
│                                                        │
│  Ed API token    [_______________________________]     │
│                  Get yours at edstem.org/settings/     │
│                  api-tokens                            │
│                                                        │
│  Requested by:   Claude (claude.ai)                    │
│  Permissions:                                          │
│   [x] Read your Ed courses, lessons, threads           │
│   [ ] Submit quiz answers on your behalf               │
│                                                        │
│           [ Sign in & Authorize ]                      │
└────────────────────────────────────────────────────────┘
```

Notes:
- Sign-in / sign-up is an explicit tab. Avoids "wrong password creates a new account" mishaps.
- For returning users, the Ed token field is rendered but disabled with the helper text "Only fill this in if your existing connection has expired." Front-end logic enables it when needed.
- The permissions checkboxes correspond directly to OAuth scopes (§7).
- Form must include a CSRF token (planned for M4 hardening).
- No "forgot password" flow. Recovery is handled by the operator (you) via DB access. This is acceptable given the small, trusted user base.

### 3.3 Sign-in vs sign-up handling

**Decision ▸** Two valid approaches:
- A. Auto-detect: known email → sign in, unknown email → sign up. Simple, but "wrong password creates a new account" is a real footgun.
- B. Explicit tab. User picks intent, errors are unambiguous.

**Recommendation: B.** Locked into §3.2.

### 3.4 `/authorize` POST state machine

```
POST /authorize
  ├─ parse form: tab, email, password [, confirmPassword], edToken, scopes, csrfToken
  ├─ validate CSRF
  ├─ if tab == "signup":
  │    ├─ email already exists?      -> 422 "use Sign in"
  │    ├─ password meets policy?     (>= 10 chars, not in pwned list optional)
  │    ├─ password == confirm?       -> 422 if not
  │    ├─ create user (bcrypt hash)
  │    └─ goto verify_ed_token
  ├─ else (signin):
  │    ├─ user not found             -> 401 "invalid email or password" (vague on purpose)
  │    ├─ bcrypt mismatch            -> 401 same message
  │    ├─ if edToken empty AND existing ed_credentials valid -> skip to issue_code
  │    └─ goto verify_ed_token
  ├─ verify_ed_token:
  │    ├─ GET edstem.org/api/user with Bearer edToken
  │    ├─ failure                    -> 422 "Ed token invalid", redisplay form preserving other fields
  │    └─ record ed_user_id, ed_user_name
  ├─ encrypt(edToken) -> upsert ed_credentials
  ├─ issue_code:
  │    ├─ scopes = (user-checked) ∩ (client-requested) ∩ (server-supported)
  │    ├─ create authorization_code (10 min TTL)
  │    └─ 302 -> params.redirectUri?code=...&state=...
```

### 3.5 Password policy (M2)

- Minimum 10 characters.
- No additional complexity rules (mixed case, symbols, etc.) — modern guidance favors length over complexity.
- Optionally: check against a small embedded list of the 10k most common passwords.
- bcrypt with cost factor 12.
- No password reset email. If a user forgets, they contact the operator who can reset via a CLI tool (`npm run admin -- reset-password <email>`) or just delete the user row and let them sign up fresh.

---

## 4. Data Model

### 4.1 Schema (SQLite, M1)

```sql
-- migrations/001_init.sql
CREATE TABLE users (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  display_name    TEXT,
  created_at      INTEGER NOT NULL,
  last_login_at   INTEGER
);

CREATE TABLE ed_credentials (
  user_id           INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  ciphertext        BLOB NOT NULL,
  iv                BLOB NOT NULL,
  auth_tag          BLOB NOT NULL,
  ed_user_id        INTEGER,
  ed_user_name      TEXT,
  is_invalid        INTEGER NOT NULL DEFAULT 0,    -- soft flag set on Ed 401
  last_verified_at  INTEGER NOT NULL,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
);

CREATE TABLE oauth_clients (
  client_id    TEXT PRIMARY KEY,
  client_data  TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE TABLE oauth_authorization_codes (
  code            TEXT PRIMARY KEY,
  client_id       TEXT NOT NULL,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  scopes          TEXT NOT NULL,
  resource        TEXT,
  expires_at      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL
);

CREATE TABLE oauth_access_tokens (
  token         TEXT PRIMARY KEY,
  client_id     TEXT NOT NULL,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes        TEXT NOT NULL,
  resource      TEXT,
  expires_at    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,
  refresh_token TEXT
);

CREATE TABLE oauth_refresh_tokens (
  token       TEXT PRIMARY KEY,
  client_id   TEXT NOT NULL,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scopes      TEXT NOT NULL,
  resource    TEXT,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE INDEX idx_access_tokens_user ON oauth_access_tokens(user_id);
CREATE INDEX idx_refresh_tokens_user ON oauth_refresh_tokens(user_id);
CREATE INDEX idx_codes_expires ON oauth_authorization_codes(expires_at);
```

### 4.2 Driver and migrations

- **Driver: `better-sqlite3`** — synchronous, fast, zero native build complications on supported platforms.
- **No ORM.** Hand-written SQL with a thin `src/db/queries.ts` wrapper. ORMs add migration tooling complexity that this project does not need.
- **Migrations: numbered SQL files** under `src/db/migrations/`. A boot-time `applyMigrations()` records applied versions in `schema_migrations(version, applied_at)`.
- **WAL mode** enabled at boot for concurrent reads.

---

## 5. Ed Token Encryption

### 5.1 Algorithm

AES-256-GCM via Node's built-in `crypto`.

### 5.2 Key management

- `MASTER_KEY` env var: 32 bytes, base64-encoded.
- On boot: validate length and base64 format; exit the process if invalid or missing. Never run with a weak or missing key.
- Operationally: store the key in a secrets manager (1Password, Doppler, AWS Secrets Manager) and inject as env. Never commit to repo, never log.

### 5.3 Implementation

```ts
// src/credentials/crypto.ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface EncryptedToken {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export function encryptToken(plaintext: string, masterKey: Buffer): EncryptedToken {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  return { ciphertext, iv, authTag: cipher.getAuthTag() };
}

export function decryptToken(record: EncryptedToken, masterKey: Buffer): string {
  const decipher = createDecipheriv('aes-256-gcm', masterKey, record.iv);
  decipher.setAuthTag(record.authTag);
  const plaintext = Buffer.concat([
    decipher.update(record.ciphertext),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}
```

### 5.4 No envelope encryption

**Decision ▸** Direct KEK encryption only. No envelope (KEK + per-row DEK).

Rationale: envelope only pays off when key rotation is a real, scheduled requirement. For a small self-hosted deployment with no compliance regime, it adds complexity without proportionate benefit. If rotation ever becomes necessary, the `MASTER_KEY_PREVIOUS` pattern (decrypt with old, re-encrypt with new in a one-shot script) is enough.

### 5.5 Verify-before-store

Logic ported from `edstem-cli/edstem_cli/auth.py:75 verify_token` (covers 401/403, 3xx redirects, non-JSON responses):

```ts
// src/credentials/verifier.ts
export async function verifyEdToken(
  token: string,
  apiBaseUrl: string,
): Promise<{ edUserId: number; edUserName: string }> {
  // GET ${apiBaseUrl}user with Bearer ${token}, redirect: 'manual'
  // 401/403            -> throw EdTokenInvalidError
  // 3xx                -> throw EdApiBaseUrlError
  // non-JSON body      -> throw EdApiBaseUrlError
  // 2xx with user      -> return { edUserId, edUserName }
}
```

Invalid tokens **never reach the database**. Without this, users save broken tokens and only discover the failure on their first tool call.

---

## 6. MCP Tool Integration (per-request EdClient)

### 6.1 The single change that unlocks multi-tenancy

`src/mcp/server.ts:242` currently has `createClient(config)` which reads only `config.edApiToken`. This is the one place that needs surgery.

### 6.2 Refactor

`requireBearerAuth` middleware attaches `AuthInfo` (returned from `verifyAccessToken`) to `req.auth`. The MCP SDK passes `authInfo` into tool handlers via the `extra` parameter:

```ts
// src/mcp/server.ts (after refactor)
import type { CredentialsService } from '../credentials/service.js';

export function createServer(
  config: AppConfig,
  credentials: CredentialsService,
): McpServer {
  const server = new McpServer({ name: 'edstem-mcp', version: '0.2.0' });

  const withClient = async <T>(
    extra: { authInfo?: { extra?: { userId?: number } } },
    fn: (client: EdClient) => Promise<T>,
  ): Promise<T> => {
    const userId = extra.authInfo?.extra?.userId;
    if (!userId) throw new Error('missing user context');
    const edToken = await credentials.getDecryptedEdToken(userId);
    const client = new EdClient({ apiBaseUrl: config.apiBaseUrl, token: edToken });
    return fn(client);
  };

  server.registerTool('list_courses', { /* ... */ }, async (args, extra) =>
    withClient(extra, async (client) => {
      const result = await client.fetchUser();
      return jsonResult(result.courses.map(serializeCourse));
    }),
  );

  // every other tool follows the same pattern
}
```

### 6.3 No token caching

**Decision ▸** Each tool call freshly decrypts and constructs a new `EdClient`.

Rationale: simpler reasoning, smaller in-memory footprint of plaintext secrets. AES-GCM + a single SQLite read costs well under a millisecond — orders of magnitude below the Ed API round-trip. Reconsider only if profiling later shows it matters.

---

## 7. Tool Surface and Scopes

### 7.1 Scope definitions

| Scope | Meaning | Default checked in consent UI |
|---|---|---|
| `mcp:tools.read` | Read courses, lessons, threads, activity | Yes |
| `mcp:tools.write` | Submit quiz answers, submit slides | No |

The consent form's checkboxes map directly to scopes. Use plain English labels in the UI ("Read your Ed courses..."), not raw scope strings.

### 7.2 Tool migration matrix

| CLI command | MCP tool | Scope | Status | Milestone |
|---|---|---|---|---|
| `courses` | `list_courses` | read | ✅ done | — |
| `lessons list` | `list_lessons` | read | ✅ done | — |
| `lesson` | `get_lesson` | read | ✅ done | — |
| `lessons questions` | `list_slide_questions` | read | ✅ done | — |
| `lessons responses` | `list_slide_responses` | read | ✅ done | — |
| `threads`, `thread` | `list_threads`, `get_thread`, `get_course_thread` | read | ✅ done | — |
| `activity` | `list_activity` | read | ✅ done | — |
| (none) | `get_user` | read | ✅ done | — |
| `lessons quiz` (view) | combo of read tools above | read | ✅ done | — |
| `lessons answer` | `submit_slide_answer` | **write** | ❌ pending | M3 |
| `lessons submit` | `submit_slide` | **write** | ❌ pending | M3 |
| `skills *` | — | — | not migrated (CLI-only) | — |

### 7.3 Annotations for write tools

```ts
const WRITE_ANNOTATIONS = {
  destructiveHint: true,
  readOnlyHint: false,
} as const;
```

This signals to the client LLM that these tools have side effects and warrant extra caution.

### 7.4 Per-tool scope enforcement

`requireBearerAuth` is configured with `requiredScopes: [READ_SCOPE]` (every authenticated request needs read). Write tools additionally check the bearer's scope set inside the handler and return `INSUFFICIENT_SCOPE` if missing — the SDK does not currently support per-tool scope declarations.

---

## 8. Error Handling and Reauth

### 8.1 Ed 401 → client reconnect prompt

When a tool call receives 401 from Ed:

1. `EdClient.get` throws `EdAuthExpiredError` (a subclass of `EdApiError` with `kind: 'auth_expired'`).
2. The tool handler catches it, calls `credentials.markInvalid(userId)` (sets `is_invalid = 1`, keeps the row for audit).
3. Returns a JSON-RPC error to the MCP client:
   ```json
   {
     "jsonrpc": "2.0",
     "id": <req_id>,
     "error": {
       "code": -32001,
       "message": "Ed Discussion credentials expired or invalid",
       "data": {
         "type": "EDSTEM_REAUTH_REQUIRED",
         "reconnect_url": "https://your-mcp-host/reconnect?return_to=..."
       }
     }
   }
   ```
4. Each write-tool description mentions: "If you receive `EDSTEM_REAUTH_REQUIRED`, ask the user to visit `reconnect_url` to refresh their Ed connection."

### 8.2 OAuth access token is **not** revoked on Ed expiry

**Decision ▸** Only the Ed credential is invalidated. The OAuth access token stays valid.

Rationale: the user's identity with our server has not changed. Forcing a full sign-in just to re-paste an Ed token creates friction without security benefit (we still hold the OAuth issuance, no third-party credential leaked). The `/reconnect` page handles the lightweight Ed-token-only flow.

### 8.3 Error code map

| Scenario | JSON-RPC code | `data.type` |
|---|---|---|
| Bearer missing or expired | (handled by SDK, HTTP 401) | — |
| User has no `ed_credentials` row | -32001 | `EDSTEM_NOT_CONNECTED` |
| Ed credential flagged invalid | -32001 | `EDSTEM_REAUTH_REQUIRED` |
| Ed 4xx business error (e.g. lesson not found) | -32000 | `EDSTEM_API_ERROR` |
| Ed 5xx or network failure | -32000 | `EDSTEM_UPSTREAM_ERROR` |
| Bearer lacks required scope | -32002 | `INSUFFICIENT_SCOPE` |

---

## 9. Roadmap

Each milestone is independently shippable.

### M1 — Data layer migration (1–2 weeks)

**Goal:** keep behaviour identical (single admin user) but replace JSON file storage with SQLite. Zero UX change.

**Tasks:**
- [ ] Add deps: `better-sqlite3`, `@types/better-sqlite3`
- [ ] `src/db/connection.ts` — singleton `Database` instance, WAL mode on boot
- [ ] `src/db/migrations/001_init.sql` — OAuth tables + `schema_migrations`
- [ ] `src/db/migrate.ts` — apply migrations at startup
- [ ] `src/oauth/sql-store.ts` — implement `OAuthRegisteredClientsStore` and full OAuth CRUD
- [ ] Update `src/oauth/provider.ts` to inject `SqlOAuthStore` instead of `FileOAuthStore`
- [ ] Update `src/config.ts`: drop `storePath`, add `databasePath` (default `.data/edstem-mcp.db`)
- [ ] Delete `src/oauth/store.ts` (FileOAuthStore)
- [ ] Optional one-shot migration script: import `.data/oauth-store.json` into SQLite
- [ ] Tests: `test/oauth/sql-store.test.ts` covering client / code / token lifecycles

**Definition of Done:**
- All existing vitest tests pass.
- Manual OAuth flow walkthrough succeeds: discovery → `/authorize` → `/token` → tool call.
- Restarting the server preserves issued access tokens.
- Removing `.data/oauth-store.json` and restarting still works (data lives in SQLite now).
- **Gate: connect from claude.ai's real connector UI to a dev instance and confirm the OAuth handshake completes end-to-end.** This catches SDK / spec interop issues early — before they compound under M2's larger surface area.

### M2 — Multi-user accounts and encrypted Ed token capture (2–3 weeks)

**Goal:** anyone can sign up, sign in, and connect their own Ed account. OAuth tokens are bound to specific users.

**Tasks:**
- [ ] `src/db/migrations/002_users.sql`, `003_ed_credentials.sql`
- [ ] `src/users/service.ts` — bcrypt (cost 12), `register`, `authenticate`, `findByEmail`
- [ ] `src/users/repository.ts` — SQL queries
- [ ] `src/credentials/crypto.ts` — `encryptToken` / `decryptToken`
- [ ] `src/credentials/verifier.ts` — `verifyEdToken` (calls Ed `GET /user`)
- [ ] `src/credentials/service.ts` — `connect`, `getDecryptedEdToken`, `markInvalid`
- [ ] `src/credentials/repository.ts`
- [ ] Rewrite `src/oauth/login-page.ts` — tab switcher, ed_token field, scope checkboxes, error redisplay (CSRF placeholder for M4)
- [ ] Rewrite `EdstemOAuthProvider.authorize()` — implement state machine in §3.4
- [ ] Update `EdstemOAuthProvider.verifyAccessToken` to surface `userId` (DB id, not username) in `AuthInfo.extra`
- [ ] Update `src/mcp/server.ts` — every tool handler uses `withClient(extra, ...)` pattern from §6.2
- [ ] Update `src/config.ts`:
  - Remove `OAUTH_USERNAME` / `OAUTH_PASSWORD` / `OAUTH_USER_*` env vars
  - Make `ED_API_TOKEN` optional, dev-only fallback for local testing
  - Add required `MASTER_KEY` (32-byte base64), validated at boot
- [ ] Add `npm run admin -- reset-password <email>` CLI helper (operator-only password reset)
- [ ] Tests:
  - `test/credentials/crypto.test.ts` — round-trip encrypt/decrypt, tag tampering rejected
  - `test/users/service.test.ts` — duplicate email rejected, wrong password rejected, bcrypt verified
  - `test/oauth/multi-user.test.ts` — user A's token cannot retrieve user B's data
- [ ] Update README

**Definition of Done:**
- Two distinct accounts (each with their own Ed token) can connect simultaneously and never see each other's data.
- Restarting the server preserves both connections.
- Saving an empty or invalid Ed token returns 422 and does not write to the DB.
- Server fails to start without `MASTER_KEY`.

### M3 — Full tool surface and write scope (1–2 weeks)

**Goal:** MCP capability matches the CLI's read + write operations. Scopes enforced.

**Tasks:**
- [ ] Extend `EdClient` with write methods:
  - `submitSlideAnswer(questionId, choices, { amend })` → POST to the responses endpoint
  - `submitSlide(slideId)` → POST to the slide submit endpoint
  - Endpoint paths: cross-reference `edstem-cli/edstem_cli/client.py`
- [ ] Register MCP tools `submit_slide_answer`, `submit_slide` with `WRITE_ANNOTATIONS`
- [ ] `src/oauth/provider.ts`:
  - `normalizeRequestedScopes` accepts both `mcp:tools.read` and `mcp:tools.write`
  - Issued tokens carry exactly the user-checked subset
- [ ] Per-tool write-scope enforcement helper used by every write tool handler
- [ ] Each write tool's description clearly states "this submits on the user's behalf"
- [ ] Tests covering scope rejection and a real write round-trip against a dev Ed account

**Definition of Done:**
- A read-only token rejected from write tools with `INSUFFICIENT_SCOPE`.
- A write-scoped token successfully submits a quiz answer in a dev environment.
- claude.ai consent UI shows both permission options separately.

### M4 — Production hardening (1–2 weeks)

**Goal:** safe to expose on the public internet for a small group.

**Tasks:**
- [ ] CSRF protection on all POST endpoints (`/authorize`, `/settings/*`, `/reconnect`) — double-submit cookie pattern
- [ ] Structured logging with `pino`, every line tagged with `request_id`, `user_id`, `tool_name`
- [ ] Per-user rate limiting via `express-rate-limit` (in-memory store, key = userId or IP for unauthenticated routes)
- [ ] `Dockerfile` (multi-stage, non-root user) and `docker-compose.yml` (app + Caddy as TLS terminator)
- [ ] `/healthz` (liveness) and `/readyz` (DB reachable + master key loaded) endpoints
- [ ] Graceful shutdown on SIGTERM (drain in-flight requests, close DB)
- [ ] `/settings` page — view connection status, rotate Ed token, delete account
- [ ] `/reconnect` page — minimal flow that only collects an Ed token (used by the §8.1 reauth UX)
- [ ] Backup guidance in `OPERATIONS.md`: SQLite file copy via `sqlite3 .backup`, off-host storage cron
- [ ] Security review checklist: §11 risks audited

**Definition of Done:**
- Running on a public hostname behind HTTPS (Let's Encrypt via Caddy).
- A modest load test (10 concurrent users × 2 RPS for 5 minutes) holds error rate < 1%, p95 < 500ms.
- `docker-compose up -d` brings the whole stack up from a clean checkout with only `MASTER_KEY` set in env.
- Backup procedure is documented and tested by restoring from a backup into a fresh container.

---

## 10. Engineering Practices

### 10.1 Directory layout (after M2)

```
src/
├─ index.ts                  # express app bootstrap
├─ config.ts                 # env parsing + validation
├─ db/
│  ├─ connection.ts          # better-sqlite3 singleton, WAL setup
│  ├─ migrate.ts             # apply migrations on boot
│  └─ migrations/
│     ├─ 001_init.sql
│     ├─ 002_users.sql
│     └─ 003_ed_credentials.sql
├─ users/
│  ├─ service.ts             # register, authenticate, findByEmail
│  └─ repository.ts          # SQL queries
├─ credentials/
│  ├─ crypto.ts              # AES-GCM encrypt/decrypt
│  ├─ verifier.ts            # call Ed /user
│  ├─ service.ts             # connect, getDecryptedEdToken, markInvalid
│  └─ repository.ts
├─ oauth/
│  ├─ provider.ts            # EdstemOAuthProvider (refactored)
│  ├─ sql-store.ts           # SQL-backed OAuth store
│  ├─ session.ts             # kept for the authorize-page session, reviewed in M4
│  └─ login-page.ts          # single-screen HTML render
├─ ed/
│  ├─ client.ts              # EdClient (M3 adds write methods)
│  ├─ models.ts
│  ├─ serialization.ts
│  └─ filter.ts
└─ mcp/
   └─ server.ts              # tool registry (M2 refactored to per-request)

test/                        # mirrors src/
```

### 10.2 Testing strategy

- **Unit:** crypto, verifier, users/service, credentials/service, OAuth SQL store.
- **Integration:** in-memory SQLite + real OAuth flow via `supertest` against the Express app.
- **End-to-end:** scripted MCP client flow covering register → connect Ed → read tool → write tool → simulated Ed 401 → reconnect → retry.
- **Do not mock the Ed API:** instead, run a small fake Ed server fixture for CI. CLI authors already learned this lesson — mocked auth + real prod auth diverge eventually.

### 10.3 Environment variables (after M2)

| Env | Required | Default | Purpose |
|---|---|---|---|
| `MASTER_KEY` | ✅ | — | 32 bytes base64. AES-256-GCM key for Ed tokens |
| `DATABASE_PATH` | ❌ | `.data/edstem-mcp.db` | SQLite file location |
| `PORT` | ❌ | `8787` | HTTP listen port |
| `MCP_PATH` | ❌ | `/mcp` | MCP transport mount path |
| `PUBLIC_BASE_URL` | ❌ | `http://localhost:${PORT}` | Externally reachable base URL (OAuth issuer) |
| `OAUTH_ACCESS_TOKEN_TTL_SECONDS` | ❌ | `3600` | |
| `OAUTH_REFRESH_TOKEN_TTL_SECONDS` | ❌ | `2592000` | |
| `ED_API_BASE_URL` | ❌ | `https://edstem.org/api/` | |
| `ED_API_TOKEN` | ❌ | — | Dev-only fallback. Must be unset in production |
| `LOG_LEVEL` | ❌ | `info` | Active after M4's pino integration |
| `MASTER_KEY_PREVIOUS` | ❌ | — | Optional, used only during a key rotation window |

---

## 11. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Ed API rate-limits per IP rather than per token | All users share one egress IP and trigger throttling | Confirm with a dev account before M4. If IP-limited, add a small per-user request budget |
| claude.ai connector OAuth has spec quirks not covered by the SDK defaults | M2 ships but claude.ai cannot connect | M1's mandatory claude.ai live-connect gate catches this before M2 starts |
| `MASTER_KEY` leaks (operator mistake, host compromise) | All stored Ed tokens become decryptable | Store key in a secrets manager, never log, rotate on suspicion using `MASTER_KEY_PREVIOUS` |
| User enters a wrong Ed token repeatedly and triggers Ed account lockout | User support burden | Verifier enforces backoff after N failures within a short window; UI offers a clear "where to find your token" link |
| SQLite + multi-process | Lost writes | Run a single Express process. If horizontal scale is ever needed, swap the storage layer |

---

## 12. Decisions to Confirm

After the previous round of decisions, the following remain (recommended values in bold):

1. **§3.3** — Sign-in vs sign-up via explicit tabs, not auto-detect. **(Recommend: yes)**
2. **§5.4** — Skip envelope encryption; encrypt directly with `MASTER_KEY`. **(Recommend: yes)**
3. **§6.3** — Do not cache decrypted Ed tokens. **(Recommend: yes)**
4. **§8.2** — Do not revoke OAuth access tokens when an Ed credential expires. **(Recommend: yes)**
5. **§9 M1 gate** — Mandatory claude.ai live-connection dry-run as a hard gate before M2 begins. **(Recommend: yes)**

Confirm these and M1 is ready to start.

---

## Appendix A: References

- MCP specification: https://spec.modelcontextprotocol.io/
- MCP TS SDK auth modules: `@modelcontextprotocol/sdk/server/auth/*`
- claude.ai connector docs: TBD (capture during M1 dry-run)
- EdStem API: no public documentation; use `edstem-cli/edstem_cli/client.py` as the reference for endpoint shapes and error semantics
- AES-GCM in Node: https://nodejs.org/api/crypto.html#class-cipher

## Appendix B: Relationship to edstem-cli

- **No code sharing.** The two projects are separate. CLI serves local developers; MCP serves remote LLM clients.
- **Shared design knowledge.** Endpoint paths, field naming, filter logic, and especially error-handling edge cases are ported by reading the CLI source — they have already absorbed the lessons learned.
- **Future convergence (out of scope).** If the EdStem API changes shape, both repos update independently. A shared spec file is conceivable but not on this plan's roadmap.
