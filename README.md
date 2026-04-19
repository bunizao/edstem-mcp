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
bun run db:prune
```

## Environment

- Copy `.env.example` to `.env` and fill in `MASTER_KEY`.
- `MASTER_KEY`: required, 32-byte base64 key for Ed token encryption
- `DATABASE_PATH`: optional, defaults to `.data/edstem-mcp.db`
- `DB_CLEANUP_INTERVAL_SECONDS`: optional, defaults to `900`
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
cp .env.example .env
# Fill in MASTER_KEY first.
bun run start
```

Health endpoints:

- `/healthz`
- `/readyz`

## Docker

```bash
cp .env.example .env
# Fill in MASTER_KEY first.
docker compose up -d --build
```

The compose file publishes the app directly on `8787` by default.
It also ships with a `readyz` health check, init process, and periodic OAuth cleanup.

Useful overrides:

- `APP_PORT=9000` to bind another host port
- `PUBLIC_BASE_URL=http://your-host:9000` to make OAuth metadata point at the real public URL
- `DB_CLEANUP_INTERVAL_SECONDS=300` to prune expired OAuth rows every 5 minutes

No reverse proxy is included. If you want TLS later, put one in front yourself.

## Backup

Use the included scripts:

```bash
./scripts/backup-db.sh .data/edstem-mcp.db
./scripts/restore-db.sh backups/edstem-mcp-YYYYMMDD-HHMMSS.db .data/edstem-mcp.db
```

For restores, stop the app first. For Docker deployments, point the scripts at the mounted volume path.
