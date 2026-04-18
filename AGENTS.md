# AGENTS.md

Operating manual for AI coding agents (Claude Code, Codex, Cursor, etc.) and new human contributors working on this repository.

> Read this before making changes. It describes what this project is, how to run and test it, the conventions to follow, and the things never to do.

---

## What this project is

`edstem-mcp` is a remote [Model Context Protocol](https://spec.modelcontextprotocol.io/) server that exposes the Ed Discussion (`edstem.org`) API as MCP tools, so any MCP-compatible client (claude.ai connector, Cursor, Claude Desktop, custom SDKs) can query and interact with EdStem on a user's behalf.

It is the network-deployed sibling of [`edstem-cli`](../edstem-cli) (a local Python CLI). The two are independent codebases; nothing is imported across them. When in doubt about EdStem API behaviour, consult `edstem-cli/edstem_cli/client.py` as the reference implementation.

The end-to-end implementation roadmap is in [`PLAN.md`](./PLAN.md). Read that for the "where this is going."

---

## Tech stack

- **Runtime:** Node.js >= 20
- **Language:** TypeScript (strict mode), ESM
- **HTTP:** Express 4
- **MCP SDK:** `@modelcontextprotocol/sdk` (^1.17)
- **Schema validation:** `zod`
- **Tests:** `vitest`
- **Dev runner:** `tsx watch`
- **Database (planned, M1+):** SQLite via `better-sqlite3`

No ORM. No framework beyond Express. Keep the dependency surface small.

---

## Setup and common commands

```bash
npm install

# Required: an Ed API token from https://edstem.org/settings/api-tokens
export ED_API_TOKEN="your-ed-token"

npm run dev      # tsx watch on src/index.ts
npm run check    # tsc --noEmit, type-check only
npm run build    # compile to dist/
npm run start    # node dist/index.js (requires build first)
npm test         # vitest run
```

Server listens on `http://localhost:8787/mcp` by default.

Environment variables are documented in `README.md` and (for the planned multi-user mode) in `PLAN.md` §10.3.

---

## Repository layout

```
src/
├─ index.ts              # Express bootstrap, route mounting
├─ config.ts             # env parsing and validation
├─ ed/                   # EdStem API client and domain types
│  ├─ client.ts          # HTTP client; Bearer auth; error mapping
│  ├─ models.ts          # TS types matching Ed JSON
│  ├─ serialization.ts   # to-MCP-payload converters
│  └─ filter.ts          # post-fetch filtering helpers
├─ mcp/
│  └─ server.ts          # MCP tool registry; one server per request
├─ oauth/                # OAuth 2.1 + PKCE provider for MCP auth
│  ├─ provider.ts        # EdstemOAuthProvider implementing OAuthServerProvider
│  ├─ store.ts           # FileOAuthStore (to be replaced by SQL store in M1)
│  ├─ session.ts         # signed cookie session for /authorize page
│  └─ login-page.ts      # HTML form rendering
test/                    # mirrors src/
dist/                    # build output (gitignored)
.data/                   # runtime state (gitignored)
```

Planned additions per `PLAN.md`:
- `src/db/` — SQLite connection, migrations
- `src/users/` — account model
- `src/credentials/` — Ed token encryption and verification

---

## Code conventions

### Style

- TypeScript strict mode. No `any`, prefer `unknown` and narrow.
- ESM imports use `.js` suffix even in TS files (Node ESM requirement).
- Async/await throughout. No bare promises returned from non-handler code.
- Use `node:` prefix for built-in modules (`node:crypto`, `node:fs/promises`).
- One concept per file. Keep modules small and focused.

### Comments

- **Comments are written in English only.** No exceptions, regardless of conversation language.
- Default to no comments. Identifier names should make code self-explanatory.
- Add a comment only when the *why* is non-obvious — invariants, workarounds for upstream bugs, surprising constraints.
- Never describe *what* the code does (that's what reading it is for).
- Never reference the current task, ticket, or session ("added for the multi-user refactor", "fixes issue #42") — that belongs in commit messages and PR descriptions.

### Naming

- Files: `kebab-case.ts`
- Types and classes: `PascalCase`
- Functions, variables, fields: `camelCase`
- Constants: `UPPER_SNAKE_CASE`
- Tool names (MCP-facing): `snake_case` (e.g. `list_courses`, `submit_slide_answer`)

### Error handling

- HTTP / external errors map to typed errors (`EdApiError` and its subclasses) with structured fields, not just `Error`.
- MCP tool errors use the JSON-RPC error envelope with a stable `data.type` discriminator (see `PLAN.md` §8.3).
- Don't swallow errors. If a layer can't handle one, let it propagate or rewrap with context.
- Validate at boundaries (inbound HTTP, env vars, untrusted JSON) using `zod`. Trust internal call sites.

---

## Architectural rules (do not violate)

These come from the project's threat model and are explicit decisions, not preferences.

1. **Per-user Ed token isolation.** Every MCP tool call must use the *requesting* user's Ed token, resolved from `req.auth.extra.userId`. Never read a global token in tool handlers. (The current `config.edApiToken` path is legacy — `PLAN.md` M2 removes it.)

2. **Ed tokens are sensitive secrets.** Once `PLAN.md` M2 lands:
   - Ed tokens are AES-256-GCM encrypted at rest.
   - Plaintext exists only on the request stack frame that needs it.
   - **Never** log a token (or anything that could be a token), even at debug level.
   - **Never** add a token to error messages, exception payloads, or audit records.

3. **Verify before storing.** Any Ed token submitted by a user is validated against `GET /user` *before* persistence. Invalid tokens never reach the database.

4. **Read vs write scope separation.** OAuth scope `mcp:tools.write` is a separate, opt-in grant. Write tools *must* enforce it inside their handler — the SDK does not currently support per-tool scope declarations.

5. **No mocking external auth in tests.** Use a fake Ed server fixture if needed, but do not mock the verifier / client at the unit level for integration tests. Real failure modes (3xx redirects, non-JSON bodies, 401 vs 403) only surface in integration shape.

6. **Single-process SQLite.** Run one Express process. Do not introduce multi-worker or clustering until the storage layer is swapped (see `PLAN.md` risks).

---

## How to do common tasks

### Add a new MCP tool

1. If the underlying Ed endpoint isn't covered, add a method to `EdClient` first (use existing methods as the pattern; reuse `parseUser` / `parseThread` / etc.).
2. Add a serializer in `src/ed/serialization.ts` if the response shape needs flattening for MCP.
3. Register the tool in `src/mcp/server.ts`:
   - Pick a `snake_case` name.
   - Use `READ_ONLY_ANNOTATIONS` for read tools, `WRITE_ANNOTATIONS` for write tools (M3+).
   - Define `inputSchema` with zod.
   - Inside the handler, use the `withClient(extra, ...)` pattern (M2+) — never instantiate a client from `config.edApiToken`.
4. Write a unit test covering at least the happy path and one error path.

### Add a new OAuth scope

Don't, unless `PLAN.md` says so. Scopes are part of the public consent contract. Adding one is a UX and security review.

### Add a new env var

1. Add it to `src/config.ts` with explicit parsing and a default (or required-ness check).
2. Document it in `README.md`.
3. If runtime-relevant, add it to the env table in `PLAN.md` §10.3.

### Add a new DB migration (M1+)

1. Create `src/db/migrations/NNN_name.sql` with the next number.
2. Make it idempotent if reasonable (`CREATE TABLE IF NOT EXISTS`, etc.).
3. Never edit a migration after it has been applied to any environment — write a new migration instead.

---

## Testing

Run `npm test` before sending any change. Specifically:

- Anything touching `src/ed/` requires updates to `test/` mirror.
- Anything touching `src/oauth/` or `src/credentials/` (M2+) requires both unit and integration coverage.
- Type-check via `npm run check` if you changed types or signatures.
- For MCP tool changes, manually walk through one OAuth + tool-call cycle against a dev server.

---

## Things to avoid

- **Do not commit secrets.** No real Ed tokens, no `MASTER_KEY` values, no test credentials in fixtures.
- **Do not introduce an ORM.** Hand-written SQL is the chosen approach (`PLAN.md` §4.2).
- **Do not add Postgres / Redis / Kafka / message queues.** This server is intentionally single-process, single-store. If something seems to need a queue, raise it before implementing.
- **Do not weaken auth for convenience.** No "allow anonymous access for development" middleware that someone might forget to disable. Use a dev-only `ED_API_TOKEN` env fallback if needed (planned in M2).
- **Do not auto-create accounts on sign-in failure.** Sign-up and sign-in are explicit, separate flows (`PLAN.md` §3.3).
- **Do not cache plaintext Ed tokens** without an explicit decision in `PLAN.md`. Currently: do not cache.
- **Do not skip pre-commit hooks** (`--no-verify`, etc.). Fix the root cause of any failure.
- **Do not produce documentation files unprompted.** Edit existing docs; create new files only when the user asks.

---

## When in doubt

- For **architectural questions**, check `PLAN.md` first. If unanswered, ask before implementing.
- For **EdStem API behaviour**, consult `edstem-cli/edstem_cli/client.py` and `edstem-cli/edstem_cli/auth.py`. Their error-handling logic is battle-tested.
- For **MCP protocol questions**, the SDK source under `node_modules/@modelcontextprotocol/sdk` is the authority; the spec docs lag.
- For **anything destructive** (deleting migrations, force-pushing, dropping tables), stop and confirm with a human first.
