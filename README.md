# edstem-mcp

Use Ed Discussion from any MCP client.

Public service URL: [https://edstem.tuuhub.com/mcp](https://edstem.tuuhub.com/mcp)

## Quick Start

1. Add the service URL to your MCP client.
2. When the browser opens, paste your Ed API token.
3. Grant `mcp:tools.read`, and `mcp:tools.write` only if you want write tools.

Get your token here: [https://edstem.org/settings/api-tokens](https://edstem.org/settings/api-tokens)

Only an Ed API token is needed. One token is treated as one user and verified with `GET /api/user`.

## What It Can Do

- View your Ed profile and enrolled courses
- Browse lessons, slides, threads, and activity
- Open thread details by thread ID or course thread number
- Submit slide answers and submit slides if you grant write access

## Self-Hosting

Ignore this if you are just using the public service.

- Bun 1.3+
- `MASTER_KEY` as a 32-byte base64 string

### Docker

```bash
cp .env.example .env
# Fill in MASTER_KEY and PUBLIC_BASE_URL first.
docker compose pull
docker compose up -d
```

### Local Run

```bash
bun install
cp .env.example .env
# Fill in MASTER_KEY and PUBLIC_BASE_URL first.
bun run start
```

Docker image: [ghcr.io/bunizao/edstem-mcp](https://ghcr.io/bunizao/edstem-mcp)

Set `APP_IMAGE` in `.env` if you want to pin a specific tag instead of `latest`.

```bash
docker run -d --restart unless-stopped --env-file .env -p 8787:8787 -v edstem-mcp-data:/data ghcr.io/bunizao/edstem-mcp:latest
```

### Notes

- `PUBLIC_BASE_URL` must match the real external URL clients use.
- Health endpoints: `/healthz` and `/readyz`
- The image ships with a `readyz` health check.
- Backups: `./scripts/backup-db.sh .data/edstem-mcp.db`
- Restores: `./scripts/restore-db.sh backups/edstem-mcp-YYYYMMDD-HHMMSS.db .data/edstem-mcp.db`

For restores, stop the app first. For Docker deployments, point the scripts at the mounted volume path.
