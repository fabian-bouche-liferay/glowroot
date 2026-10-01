# MCP server

Glowroot exposes a [Model Context Protocol](https://modelcontextprotocol.io) server so that LLM
clients (Claude Code, Claude Desktop, IDE assistants, ...) can query monitoring data and adjust
the monitoring configuration.

It covers **transactions, traces and JVM gauges** (read), and the **slow trace threshold, gauges
and instrumentation** configuration (write).

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

Each tool call goes through the same permission checks as the UI. Reading needs for example
`agent:transaction:overview`, `agent:trace` or `agent:jvm:gauges`; configuration changes need
`agent:config:edit:transaction`, `agent:config:edit:gauges` or
`agent:config:edit:instrumentation`. A missing permission is returned as a tool error, not as an
HTTP error. Give MCP clients a dedicated user with only the permissions they need.

Use HTTPS (or a TLS terminating proxy) when the endpoint is not on localhost: Basic credentials
are sent with every request.

## Links to the UI

Tool results carry `glowrootUrl` links to the matching Glowroot page (transaction charts, the trace
modal, gauge charts, configuration pages), so that an MCP client can show its evidence to the
user. `list_traces` adds a link per trace, `create_gauge` also returns `gaugeValuesUrl`.

Links are built from the request: scheme (`X-Forwarded-Proto`, else the web server's https
setting), host (`X-Forwarded-Host`, else `Host`) and the UI context path. They are therefore
correct for the address the MCP client used to reach Glowroot.

## Tools

All times are epoch milliseconds. `from`/`to` default to the last 60 minutes.
In central mode `agentId` is required (use `list_agents`); in embedded mode it can be omitted.
Configuration tools need an agent id, not an agent rollup id.

### Read

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
| `get_trace_queries` | Queries executed during a trace, with `queryText`, sorted by total time |
| `list_gauges` | JVM gauges that have values in the time range |
| `get_gauge_values` | Values over time of one or more gauges (`gaugeNames`) |
| `get_transaction_config` | Slow trace threshold, threshold overrides, profiling interval |
| `list_gauge_configs` | Configured gauges, with the `version` used by `delete_gauge` |
| `search_mbeans` | MBean object names of the running JVM matching a partial name |
| `get_mbean_attributes` | Numeric attributes of an MBean that can become gauges |
| `list_instrumentations` | Custom instrumentation configs, and whether the JVM is out of sync |
| `search_classes` | Class names available in the monitored JVM |
| `search_methods` | Method names of a class |
| `get_method_signatures` | Signatures of a method (to target one overload) |

### Write

| Tool | Description |
|------|-------------|
| `set_slow_trace_threshold` | Default threshold, or add / update / remove a per transaction type, name, user override |
| `create_gauge` | Capture MBean attributes as gauges (`counterAttributes` are captured as a rate per second) |
| `delete_gauge` | Delete a gauge config (destructive) |
| `create_instrumentation` | Pointcut on a method: `timer`, `trace-entry`, `transaction` or `other` |
| `delete_instrumentation` | Delete instrumentation configs (destructive) |
| `apply_instrumentation_changes` | Re-weave already loaded classes so instrumentation changes take effect without a JVM restart |

Write tools are annotated `readOnlyHint: false` (and `destructiveHint: true` for deletions), so MCP
clients can ask for confirmation. Changes are logged in the Glowroot audit log like UI changes.

`create_instrumentation` uses the same defaults as a new instrumentation in the UI (any parameter
types, `capture-trace-entry` when already in a transaction, names derived from the class and
method; timer names may only contain letters, digits and spaces, the agent silently ignores
instrumentation with an invalid timer name, so the tool rejects it). Templates can use `{{0}}`, `{{1}}`... (arguments, e.g. `{{0.id}}`), `{{this}}`, `{{_}}`
(return value) and `{{methodName}}`. New instrumentation applies to classes loaded afterwards;
`apply_instrumentation_changes` is needed for classes already loaded, and requires a JVM that
supports class retransformation (the `-javaagent` agent does).

### Response shaping

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
  `CommonHandler.handleInternalGet` / `handleInternalPost`, so the data, the validation and the
  permissions are exactly those of the UI (configuration updates keep the UI's optimistic locking:
  a concurrent change is reported as a tool error).
- Basic credentials are validated on every request (password hash or LDAP bind), with no caching.
- The embedded collector jar is processed by ProGuard, which recomputes stack map frames without
  seeing the shaded Jackson classes: avoid variables (or ternaries) mixing two different Jackson
  node types in `McpServer`, they fail bytecode verification at runtime.
