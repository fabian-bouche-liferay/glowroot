# MCP server

Glowroot exposes a [Model Context Protocol](https://modelcontextprotocol.io) server so that LLM
clients (Claude Code, Claude Desktop, IDE assistants, ...) can query monitoring data.

It is **read-only** and currently covers **transactions, traces and JVM gauges**.

The endpoint is served by the same web server as the UI, in both modes:

| Mode     | Endpoint                                  |
|----------|-------------------------------------------|
| Embedded | `http://<host>:4000/mcp` (+ context path) |
| Central  | `http://<host>:4000/mcp` (+ context path) |

## Transport

- MCP *Streamable HTTP* transport, protocol versions `2025-06-18`, `2025-03-26` and `2024-11-05`.
- Stateless: `POST /mcp` with a JSON-RPC message (or batch), answered with `application/json`.
  No `Mcp-Session-Id`, no SSE stream (`GET /mcp` returns `405`).
- Requests with an `Origin` header that does not match the `Host` header are rejected (`403`), to
  prevent browsers from issuing cross-site requests.

## Authentication

HTTP Basic authentication with a Glowroot user (`Authorization: Basic base64(user:password)`).
LDAP users work as for the UI login. No session is created and the UI session cookie is ignored.

If no `Authorization` header is sent, the `anonymous` user is used, but only if it has been granted
at least one role; otherwise the server answers `401` with a `WWW-Authenticate: Basic` challenge.

Each tool call goes through the same permission checks as the UI (for example
`agent:transaction:overview`, `agent:trace`, `agent:jvm:gauges`). A missing permission is returned
as a tool error, not as an HTTP error.

Use HTTPS (or a TLS terminating proxy) when the endpoint is not on localhost: Basic credentials
are sent with every request.

## Tools

All times are epoch milliseconds. `from`/`to` default to the last 60 minutes.
In central mode `agentId` is required (use `list_agents`); in embedded mode it can be omitted.

| Tool | Description |
|------|-------------|
| `list_agents` | Agents and agent rollups that reported data in the time range |
| `list_transaction_types` | Transaction types, default transaction type, default percentiles and gauges |
| `get_transaction_summaries` | Overall summary and top transaction names (`sortOrder`, `limit`) |
| `get_transaction_overview` | Merged timer breakdown, average duration, transaction count |
| `get_transaction_percentiles` | Response time percentiles (`percentiles`, default 50/95/99) |
| `get_transaction_throughput` | Transaction count and transactions per minute |
| `get_transaction_queries` | Queries sorted by total time |
| `get_full_query_text` | Full text of a truncated query |
| `get_transaction_service_calls` | Service calls sorted by total time |
| `list_traces` | Slow traces (or error traces with `errorsOnly`) with `traceId` / `agentId` |
| `get_trace` | Trace header (headline, duration, attributes, error, timers, thread stats) |
| `get_trace_entries` | Trace entries (query entries carry an abbreviated `queryText`) |
| `get_trace_queries` | Queries executed during a trace.|
| `list_gauges` | JVM gauges that have values in the time range |
| `get_gauge_values` | Values over time of one or more gauges (`gaugeNames`) |

Trace entries and trace queries resolve the query text in place (`queryText`, plus
`fullQueryTextSha1` when Glowroot truncated it) instead of returning the UI's
`sharedQueryTextIndex` / `sharedQueryTexts` indirection.

Chart data series are omitted from the overview/percentiles/throughput tools unless
`includeChartSeries` is `true`, to keep responses small.

## Client configuration

Claude Code:

```bash
claude mcp add --transport http glowroot http://localhost:4000/mcp \
  --header "Authorization: Basic $(printf 'user:password' | base64)"
```

Generic `mcp.json`:

```json
{
  "mcpServers": {
    "glowroot": {
      "type": "http",
      "url": "http://localhost:4000/mcp",
      "headers": { "Authorization": "Basic dXNlcjpwYXNzd29yZA==" }
    }
  }
}
```

Quick check with curl:

```bash
curl -s -u user:password -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://localhost:4000/mcp
```

## Implementation notes

- `ui/src/main/java/org/glowroot/ui/McpServer.java`: JSON-RPC handling and tool definitions.
- Tool calls are dispatched in-process to the existing `/backend/...` JSON services through
  `CommonHandler.handleInternalGet`, so the data and permissions are exactly those of the UI.
- Basic credentials are validated on every request (password hash or LDAP bind), with no caching.
