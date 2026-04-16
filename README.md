# edstem-mcp

A TypeScript remote MCP server that exposes read-only Ed Discussion tools.

## Features

- Current user profile
- Enrolled courses
- Course lessons
- Lesson detail with slides
- Quiz slide questions
- Saved quiz slide responses
- Course threads
- Thread detail
- User activity

## Exposed MCP Tools

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

## Status

This first cut uses a single server-level `ED_API_TOKEN`. That is enough to build and test the MCP tools, but it is not the final public multi-user auth model for `claude.ai`.

The next auth milestone is user-bound credentials via MCP auth plus a separate Ed token connection flow.

## Requirements

- Node.js 20+
- An Ed API token from <https://edstem.org/settings/api-tokens>

## Development

```bash
npm install
export ED_API_TOKEN="your-ed-token"
npm run dev
```

The server listens on `http://localhost:8787/mcp`.

## Environment

- `ED_API_TOKEN`: Required for the current single-user development mode
- `ED_API_BASE_URL`: Optional. Defaults to `https://edstem.org/api/`
- `PORT`: Optional. Defaults to `8787`
- `MCP_PATH`: Optional. Defaults to `/mcp`

## Next Steps

- Replace the single server token with user-bound credentials
- Add MCP auth for Claude remote connector usage
- Add an Ed token connection flow and encrypted credential storage
