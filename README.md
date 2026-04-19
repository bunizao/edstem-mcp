# edstem-mcp

Bun-native remote MCP server for Ed Discussion with per-user OAuth, encrypted Ed tokens, and read/write tools.

## Requirements

- Bun 1.3+
- `MASTER_KEY` as a 32-byte base64 string

## Scripts

```bash
bun install
bun run dev
bun run test
bun run check
bun run build
bun run admin -- reset-password <email> [new-password]
```

## Environment

- `MASTER_KEY`: required, 32-byte base64 key for Ed token encryption
- `DATABASE_PATH`: optional, defaults to `.data/edstem-mcp.db`
- `PUBLIC_BASE_URL`: optional, defaults to `http://localhost:${PORT}`
- `PORT`: optional, defaults to `8787`
- `MCP_PATH`: optional, defaults to `/mcp`
- `ED_API_BASE_URL`: optional, defaults to `https://edstem.org/api/`
- `ED_API_TOKEN`: optional Bun-local fallback for development only
- `OAUTH_ACCESS_TOKEN_TTL_SECONDS`: optional, defaults to `3600`
- `OAUTH_REFRESH_TOKEN_TTL_SECONDS`: optional, defaults to `2592000`

## Tools

- `get_user`
- `list_courses`
- `list_lessons`
- `get_lesson`
- `list_slide_questions`
- `list_slide_responses`
- `list_threads`
- `get_thread`
- `get_course_thread`
- `list_activity`
- `submit_slide_answer`
- `submit_slide`

## Local Run

```bash
export MASTER_KEY="$(openssl rand -base64 32)"
bun run start
```

Health endpoints:

- `/healthz`
- `/readyz`

## Docker

```bash
MASTER_KEY="$(openssl rand -base64 32)" docker compose up -d --build
```

The compose file publishes the app directly on `8787` by default.

Useful overrides:

- `APP_PORT=9000` to bind another host port
- `PUBLIC_BASE_URL=http://your-host:9000` to make OAuth metadata point at the real public URL

Example:

```bash
MASTER_KEY="$(openssl rand -base64 32)" \
APP_PORT=9000 \
PUBLIC_BASE_URL=http://your-host:9000 \
docker compose up -d --build
```

No reverse proxy is included. If you want TLS later, put one in front yourself.

## Backup

Copy the SQLite file at `DATABASE_PATH`. For a clean snapshot, stop the app first or use `sqlite3 .backup`.
