# edstem-mcp

Use Ed Discussion from any MCP client.

## Quick Start

1. Add the service URL to your MCP client.
2. Sign in with your Ed API token.
3. Grant `mcp:tools.read`, and `mcp:tools.write` only if you want write tools.

Get your token here: [https://edstem.org/settings/api-tokens](https://edstem.org/settings/api-tokens)

No country code is needed. This uses the same Ed API token flow as [edstem-cli](https://github.com/bunizao/edstem-cli): the token is verified with `GET /api/user`.

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
docker compose up -d --build
```

### Local Run

```bash
bun install
cp .env.example .env
# Fill in MASTER_KEY and PUBLIC_BASE_URL first.
bun run start
```

Docker image: [ghcr.io/bunizao/edstem-mcp](https://ghcr.io/bunizao/edstem-mcp)

```bash
docker run -d --name edstem-mcp --restart unless-stopped -p 8787:8787 -e MASTER_KEY=YOUR_BASE64_32_BYTE_KEY -e PUBLIC_BASE_URL=https://your-host.example -e DATABASE_PATH=/data/edstem-mcp.db -v edstem-mcp-data:/data ghcr.io/bunizao/edstem-mcp:latest
```

### Notes

- `PUBLIC_BASE_URL` must match the real external URL clients use.
- Health endpoints: `/healthz` and `/readyz`
- The image ships with a `readyz` health check.
- Backups: `./scripts/backup-db.sh .data/edstem-mcp.db`
- Restores: `./scripts/restore-db.sh backups/edstem-mcp-YYYYMMDD-HHMMSS.db .data/edstem-mcp.db`

For restores, stop the app first. For Docker deployments, point the scripts at the mounted volume path.
