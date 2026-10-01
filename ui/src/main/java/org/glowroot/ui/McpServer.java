/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.glowroot.ui;

import java.io.StringWriter;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.google.common.net.MediaType;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.glowroot.agent.api.Glowroot;
import org.glowroot.common.util.Clock;
import org.glowroot.common.util.ObjectMappers;
import org.glowroot.ui.ChunkSource.ChunkCopier;
import org.glowroot.ui.CommonHandler.CommonRequest;
import org.glowroot.ui.CommonHandler.CommonResponse;
import org.glowroot.ui.HttpSessionManager.Authentication;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.MINUTES;

// Model Context Protocol server (streamable http transport, stateless, json responses only).
//
// Read-only for now: transactions, traces and jvm gauges. Every tool call is dispatched to the same
// http/json services that back the UI, so the existing permission model applies unchanged.
//
// Authentication is http basic (glowroot users, including ldap users). When no Authorization
// header is sent, the "anonymous" user is used if it has been granted any role.
class McpServer {

    static final String PATH = "/mcp";

    private static final Logger logger = LoggerFactory.getLogger(McpServer.class);

    private static final ObjectMapper mapper = ObjectMappers.create();

    private static final String LATEST_PROTOCOL_VERSION = "2025-06-18";
    private static final ImmutableList<String> SUPPORTED_PROTOCOL_VERSIONS =
            ImmutableList.of(LATEST_PROTOCOL_VERSION, "2025-03-26", "2024-11-05");

    private static final long DEFAULT_TIME_RANGE_MILLIS = MINUTES.toMillis(60);

    // json-rpc error codes
    private static final int PARSE_ERROR = -32700;
    private static final int INVALID_REQUEST = -32600;
    private static final int METHOD_NOT_FOUND = -32601;
    private static final int INVALID_PARAMS = -32602;
    private static final int INTERNAL_ERROR = -32603;

    private static final String INSTRUCTIONS = "Read-only access to Glowroot APM data."
            + " Start with list_agents (central) to get an agentId (embedded mode has a single"
            + " agent, agentId can be omitted), then list_transaction_types. Times are epoch"
            + " milliseconds; from/to default to the last 60 minutes. Durations from aggregates"
            + " are in nanoseconds unless the field name says otherwise.";

    private final boolean central;
    private final boolean offlineViewer;
    private final String version;
    private final HttpSessionManager httpSessionManager;
    private final Clock clock;

    private final ImmutableList<Tool> tools;

    McpServer(boolean central, boolean offlineViewer, String version,
            HttpSessionManager httpSessionManager, Clock clock) {
        this.central = central;
        this.offlineViewer = offlineViewer;
        this.version = version;
        this.httpSessionManager = httpSessionManager;
        this.clock = clock;
        tools = buildTools();
    }

    CommonResponse handle(CommonRequest request, CommonHandler commonHandler) throws Exception {
        if (!request.getMethod().equals("POST")) {
            // no server-initiated messages, so no sse stream (GET) and no session (DELETE)
            CommonResponse response = new CommonResponse(HttpResponseStatus.METHOD_NOT_ALLOWED);
            response.setHeader(HttpHeaderNames.ALLOW, "POST");
            return response;
        }
        if (!isSameOriginOrNoOrigin(request)) {
            return new CommonResponse(HttpResponseStatus.FORBIDDEN);
        }
        Authentication authentication = authenticate(request);
        if (authentication == null) {
            CommonResponse response = new CommonResponse(HttpResponseStatus.UNAUTHORIZED);
            response.setHeader(HttpHeaderNames.WWW_AUTHENTICATE,
                    "Basic realm=\"Glowroot MCP\", charset=\"UTF-8\"");
            return response;
        }
        Glowroot.setTransactionUser(authentication.caseAmbiguousUsername());
        JsonNode message;
        try {
            message = mapper.readTree(request.getContent());
        } catch (Exception e) {
            logger.debug(e.getMessage(), e);
            return jsonResponse(HttpResponseStatus.BAD_REQUEST,
                    error(null, PARSE_ERROR, "Parse error"));
        }
        if (message == null) {
            return jsonResponse(HttpResponseStatus.BAD_REQUEST,
                    error(null, INVALID_REQUEST, "Empty request"));
        }
        Backend backend = new Backend(commonHandler, authentication);
        if (message.isArray()) {
            // batching is part of protocol version 2025-03-26
            ArrayNode responses = mapper.createArrayNode();
            for (JsonNode element : message) {
                ObjectNode response = handleMessage(element, backend);
                if (response != null) {
                    responses.add(response);
                }
            }
            if (responses.size() == 0) {
                return new CommonResponse(HttpResponseStatus.ACCEPTED);
            }
            return jsonResponse(HttpResponseStatus.OK, responses);
        }
        ObjectNode response = handleMessage(message, backend);
        if (response == null) {
            // notification or response from client
            return new CommonResponse(HttpResponseStatus.ACCEPTED);
        }
        return jsonResponse(HttpResponseStatus.OK, response);
    }

    private @Nullable Authentication authenticate(CommonRequest request) throws Exception {
        if (offlineViewer) {
            return httpSessionManager.getAuthentication(request, false);
        }
        String authorization = request.getHeader(HttpHeaderNames.AUTHORIZATION);
        if (authorization == null) {
            // intentionally not looking at the session cookie, so that browsers cannot be used to
            // issue requests on behalf of a logged-in user
            Authentication anonymous = httpSessionManager.getAnonymousAuthentication();
            return anonymous.roles().isEmpty() ? null : anonymous;
        }
        if (!authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        String decoded;
        try {
            decoded = new String(BaseEncoding.base64().decode(authorization.substring(6).trim()),
                    UTF_8);
        } catch (IllegalArgumentException e) {
            logger.debug(e.getMessage(), e);
            return null;
        }
        int index = decoded.indexOf(':');
        if (index == -1) {
            return null;
        }
        return httpSessionManager.authenticateBasic(decoded.substring(0, index),
                decoded.substring(index + 1));
    }

    // protects against cross-site requests from browsers (which could otherwise carry cached basic
    // credentials), non-browser mcp clients do not send an Origin header
    private static boolean isSameOriginOrNoOrigin(CommonRequest request) {
        String origin = request.getHeader(HttpHeaderNames.ORIGIN);
        if (origin == null) {
            return true;
        }
        String host = request.getHeader(HttpHeaderNames.HOST);
        if (host == null) {
            return false;
        }
        try {
            URI originUri = new URI(origin);
            String originHost = originUri.getHost();
            if (originHost == null) {
                return false;
            }
            String authority = originUri.getPort() == -1 ? originHost
                    : originHost + ":" + originUri.getPort();
            return authority.equalsIgnoreCase(host) || originHost.equalsIgnoreCase(host);
        } catch (Exception e) {
            logger.debug(e.getMessage(), e);
            return false;
        }
    }

    private @Nullable ObjectNode handleMessage(JsonNode message, Backend backend) {
        if (!message.isObject()) {
            return error(null, INVALID_REQUEST, "Invalid request");
        }
        JsonNode id = message.get("id");
        JsonNode method = message.get("method");
        if (method == null || !method.isTextual()) {
            if (id != null && (message.has("result") || message.has("error"))) {
                // response to a server request (server never sends requests, so just ignore)
                return null;
            }
            return error(id, INVALID_REQUEST, "Invalid request");
        }
        if (id == null) {
            // notification (e.g. notifications/initialized), nothing to do
            return null;
        }
        JsonNode params = message.path("params");
        try {
            switch (method.asText()) {
                case "initialize":
                    return result(id, initialize(params));
                case "ping":
                    return result(id, mapper.createObjectNode());
                case "tools/list":
                    return result(id, listTools());
                case "tools/call":
                    return callTool(id, params, backend);
                default:
                    return error(id, METHOD_NOT_FOUND, "Method not found: " + method.asText());
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return error(id, INTERNAL_ERROR, e.getMessage());
        }
    }

    private ObjectNode initialize(JsonNode params) {
        String requestedVersion = params.path("protocolVersion").asText();
        ObjectNode result = mapper.createObjectNode();
        result.put("protocolVersion", SUPPORTED_PROTOCOL_VERSIONS.contains(requestedVersion)
                ? requestedVersion : LATEST_PROTOCOL_VERSION);
        result.putObject("capabilities").putObject("tools").put("listChanged", false);
        ObjectNode serverInfo = result.putObject("serverInfo");
        serverInfo.put("name", "glowroot");
        serverInfo.put("title", central ? "Glowroot Central" : "Glowroot");
        serverInfo.put("version", version);
        result.put("instructions", INSTRUCTIONS);
        return result;
    }

    private ObjectNode listTools() {
        ObjectNode result = mapper.createObjectNode();
        ArrayNode toolsNode = result.putArray("tools");
        for (Tool tool : tools) {
            ObjectNode toolNode = toolsNode.addObject();
            toolNode.put("name", tool.name);
            toolNode.put("description", tool.description);
            toolNode.set("inputSchema", tool.inputSchema);
            toolNode.putObject("annotations").put("readOnlyHint", true);
        }
        return result;
    }

    private ObjectNode callTool(JsonNode id, JsonNode params, Backend backend) {
        String name = params.path("name").asText();
        Tool tool = getTool(name);
        if (tool == null) {
            return error(id, INVALID_PARAMS, "Unknown tool: " + name);
        }
        // not re-assigning a JsonNode variable with an ObjectNode here (or using a ternary), since
        // proguard (embedded build) recomputes stack map frames without seeing the shaded jackson
        // classes, merges the two types into java.lang.Object and the class then fails verification
        // (Args handles non-object arguments, since JsonNode.get() returns null for them)
        JsonNode arguments = params.path("arguments");
        ObjectNode result = mapper.createObjectNode();
        String text;
        boolean isError;
        try {
            text = tool.handler.call(new Args(arguments), backend);
            isError = false;
        } catch (ToolException e) {
            text = e.getMessage();
            isError = true;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            text = "Unexpected error: " + e;
            isError = true;
        }
        ObjectNode content = result.putArray("content").addObject();
        content.put("type", "text");
        content.put("text", text);
        result.put("isError", isError);
        return result(id, result);
    }

    private @Nullable Tool getTool(String name) {
        for (Tool tool : tools) {
            if (tool.name.equals(name)) {
                return tool;
            }
        }
        return null;
    }

    private ImmutableList<Tool> buildTools() {
        List<Tool> list = Lists.newArrayList();

        list.add(new Tool("list_agents",
                "List the agents (and agent rollups) that reported data in the time range."
                        + " In embedded mode there is a single agent whose id is \"\".",
                schema().timeRange(),
                (args, backend) -> listAgents(args, backend)));

        list.add(new Tool("list_transaction_types",
                "List the transaction types of an agent (e.g. Web, Background), along with its"
                        + " default transaction type, default percentiles and default gauges.",
                schema().agentId(),
                (args, backend) -> listTransactionTypes(args, backend)));

        // ---- transactions ----

        list.add(new Tool("get_transaction_summaries",
                "Overall summary of a transaction type and the top transaction names in the time"
                        + " range (total/average duration, CPU, allocated memory, count).",
                schema().agentId().transactionType().timeRange()
                        .enumProperty("sortOrder", "Sort order (default total-time)",
                                "total-time", "average-time", "throughput", "total-cpu-time",
                                "average-cpu-time", "total-allocated-memory",
                                "average-allocated-memory")
                        .intProperty("limit", "Max number of transaction names (default 20)"),
                (args, backend) -> backend.get("/backend/transaction/summaries",
                        timeRangeParams(args)
                                .put("transaction-type", args.requiredString("transactionType"))
                                .put("sort-order", args.string("sortOrder", "total-time"))
                                .put("limit", args.integer("limit", 20)))));

        list.add(new Tool("get_transaction_overview",
                "Response time breakdown (merged timer tree, average duration, transaction count)"
                        + " for a transaction type, or a single transaction name.",
                schema().agentId().transactionType().transactionName().timeRange()
                        .includeChartSeries(),
                (args, backend) -> stripChartSeries(args,
                        backend.get("/backend/transaction/average", transactionParams(args)))));

        list.add(new Tool("get_transaction_percentiles",
                "Response time percentiles (in milliseconds) for a transaction type or name.",
                schema().agentId().transactionType().transactionName().timeRange()
                        .numberArrayProperty("percentiles",
                                "Percentiles to compute (default [50, 95, 99])")
                        .includeChartSeries(),
                (args, backend) -> {
                    List<String> percentiles = args.stringList("percentiles");
                    if (percentiles.isEmpty()) {
                        // adding to the same list, see comment in callTool() about proguard
                        percentiles.add("50");
                        percentiles.add("95");
                        percentiles.add("99");
                    }
                    return stripChartSeries(args,
                            backend.get("/backend/transaction/percentiles",
                                    transactionParams(args).putAll("percentile", percentiles)));
                }));

        list.add(new Tool("get_transaction_throughput",
                "Throughput (transaction count and transactions per minute) for a transaction type"
                        + " or name.",
                schema().agentId().transactionType().transactionName().timeRange()
                        .includeChartSeries(),
                (args, backend) -> stripChartSeries(args,
                        backend.get("/backend/transaction/throughput", transactionParams(args)))));

        list.add(new Tool("get_transaction_queries",
                "Queries (SQL, CQL, ...) executed by a transaction type or name, sorted by total"
                        + " time. Use get_full_query_text with fullQueryTextSha1 when the text"
                        + " is truncated.",
                schema().agentId().transactionType().transactionName().timeRange(),
                (args, backend) -> backend.get("/backend/transaction/queries",
                        transactionParams(args))));

        list.add(new Tool("get_full_query_text",
                "Full text of a truncated query returned by get_transaction_queries.",
                schema().agentId().stringProperty("fullQueryTextSha1",
                        "The fullQueryTextSha1 value of the query", true),
                (args, backend) -> backend.get("/backend/transaction/full-query-text",
                        agentRollupParams(args).put("full-text-sha1",
                                args.requiredString("fullQueryTextSha1")))));

        list.add(new Tool("get_transaction_service_calls",
                "Service calls (outgoing http, ...) made by a transaction type or name, sorted by"
                        + " total time.",
                schema().agentId().transactionType().transactionName().timeRange(),
                (args, backend) -> backend.get("/backend/transaction/service-calls",
                        transactionParams(args))));

        list.add(new Tool("list_traces",
                "List captured traces (slow traces, or error traces when errorsOnly is true) for a"
                        + " transaction type or name. Returns traceId and agentId to use with"
                        + " get_trace.",
                schema().agentId().transactionType().transactionName().timeRange()
                        .booleanProperty("errorsOnly", "Only list error traces (default false)")
                        .numberProperty("durationMillisLow", "Minimum duration in milliseconds")
                        .numberProperty("durationMillisHigh", "Maximum duration in milliseconds")
                        .intProperty("limit", "Max number of traces (default 100)"),
                (args, backend) -> listTraces(args, backend)));

        list.add(new Tool("get_trace",
                "Header of a trace: headline, duration, user, attributes, error, timers, thread"
                        + " stats, entry/query/profile sample counts.",
                schema().traceAgentId().traceId(),
                (args, backend) -> backend.get("/backend/trace/header", traceParams(args))));

        list.add(new Tool("get_trace_entries",
                "Trace entries (timeline of instrumented calls) of a trace.",
                schema().traceAgentId().traceId(),
                (args, backend) -> backend.get("/backend/trace/entries", traceParams(args))));

        list.add(new Tool("get_trace_queries",
                "Aggregated queries executed during a trace.",
                schema().traceAgentId().traceId(),
                (args, backend) -> backend.get("/backend/trace/queries", traceParams(args))));

        // ---- jvm gauges ----

        list.add(new Tool("list_gauges",
                "List the JVM gauges (MBean attributes such as heap usage, CPU load, thread count)"
                        + " that have values in the time range.",
                schema().agentId().timeRange(),
                (args, backend) -> {
                    JsonNode node = mapper.readTree(
                            backend.get("/backend/jvm/gauges", timeRangeParams(args)));
                    return mapper.writeValueAsString(node.path("allGauges"));
                }));

        list.add(new Tool("get_gauge_values",
                "Values over time of one or more JVM gauges. Each data series contains"
                        + " [captureTime, value] points (null marks a gap).",
                schema().agentId().timeRange()
                        .stringArrayProperty("gaugeNames",
                                "Gauge names as returned by list_gauges (field name)", true),
                (args, backend) -> {
                    List<String> gaugeNames = args.stringList("gaugeNames");
                    if (gaugeNames.isEmpty()) {
                        throw new ToolException("gaugeNames is required");
                    }
                    ObjectNode node = (ObjectNode) mapper.readTree(backend.get(
                            "/backend/jvm/gauges",
                            timeRangeParams(args).putAll("gauge-name", gaugeNames)));
                    node.remove("allGauges");
                    return mapper.writeValueAsString(node);
                }));

        return ImmutableList.copyOf(list);
    }

    private String listAgents(Args args, Backend backend) throws Exception {
        ArrayNode agents = mapper.createArrayNode();
        if (!central) {
            ObjectNode agent = agents.addObject();
            agent.put("id", "");
            agent.put("display", "embedded agent");
            return mapper.writeValueAsString(agents);
        }
        Params timeRange = new Params().put("from", args.from()).put("to", args.to());
        JsonNode topLevels =
                mapper.readTree(backend.get("/backend/top-level-agent-rollups", timeRange));
        for (JsonNode topLevel : topLevels) {
            String id = topLevel.path("id").asText();
            if (!id.endsWith("::")) {
                agents.add(agentNode(id, topLevel.path("display").asText(), false, 0,
                        topLevel.path("disabled").asBoolean()));
                continue;
            }
            agents.add(agentNode(id, topLevel.path("display").asText(), true, 0,
                    topLevel.path("disabled").asBoolean()));
            JsonNode children = mapper.readTree(backend.get("/backend/child-agent-rollups",
                    new Params().put("top-level-id", id).put("from", args.from())
                            .put("to", args.to())));
            for (JsonNode child : children) {
                String childId = child.path("id").asText();
                agents.add(agentNode(childId, child.path("display").asText(),
                        childId.endsWith("::"), child.path("depth").asInt() + 1,
                        child.path("disabled").asBoolean()));
            }
        }
        return mapper.writeValueAsString(agents);
    }

    private static ObjectNode agentNode(String id, String display, boolean rollup, int depth,
            boolean noDirectPermission) {
        ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("id", id);
        node.put("display", display);
        node.put("rollup", rollup);
        node.put("depth", depth);
        if (noDirectPermission) {
            // user only has permissions on some child agents
            node.put("noDirectPermission", true);
        }
        return node;
    }

    private String listTransactionTypes(Args args, Backend backend) throws Exception {
        JsonNode layout = mapper.readTree(backend.get("/backend/agent-rollup",
                new Params().put("id", agentId(args))));
        ObjectNode result = mapper.createObjectNode();
        result.set("transactionTypes", layout.path("transactionTypes"));
        result.set("defaultTransactionType", layout.path("defaultTransactionType"));
        result.set("defaultPercentiles", layout.path("defaultPercentiles"));
        result.set("defaultGaugeNames", layout.path("defaultGaugeNames"));
        result.set("permissions", layout.path("permissions"));
        return mapper.writeValueAsString(result);
    }

    private String listTraces(Args args, Backend backend) throws Exception {
        String path = args.bool("errorsOnly", false) ? "/backend/error/points"
                : "/backend/transaction/points";
        Params params = transactionParams(args).put("limit", args.integer("limit", 100));
        Double durationMillisLow = args.number("durationMillisLow");
        if (durationMillisLow != null) {
            params.put("duration-millis-low", durationMillisLow);
        }
        Double durationMillisHigh = args.number("durationMillisHigh");
        if (durationMillisHigh != null) {
            params.put("duration-millis-high", durationMillisHigh);
        }
        JsonNode node = mapper.readTree(backend.get(path, params));
        // convert the compact chart points [captureTime, durationMillis, agentId, traceId] into
        // self-describing objects
        ObjectNode result = mapper.createObjectNode();
        ArrayNode traces = result.putArray("traces");
        addTracePoints(traces, node.path("normalPoints"), false, false);
        addTracePoints(traces, node.path("errorPoints"), true, false);
        addTracePoints(traces, node.path("partialPoints"), false, true);
        if (node.path("limitExceeded").asBoolean()) {
            result.put("limitExceeded", true);
        }
        if (node.path("expired").asBoolean()) {
            result.put("expired", true);
        }
        return mapper.writeValueAsString(result);
    }

    private static void addTracePoints(ArrayNode traces, JsonNode points, boolean error,
            boolean partial) {
        for (JsonNode point : points) {
            ObjectNode trace = traces.addObject();
            trace.set("captureTime", point.path(0));
            trace.set("durationMillis", point.path(1));
            trace.set("agentId", point.path(2));
            trace.set("traceId", point.path(3));
            if (error) {
                trace.put("error", true);
            }
            if (partial) {
                // still in progress (or stuck)
                trace.put("partial", true);
            }
        }
    }

    private static String stripChartSeries(Args args, String json) throws Exception {
        if (args.bool("includeChartSeries", false)) {
            return json;
        }
        JsonNode node = mapper.readTree(json);
        if (node instanceof ObjectNode) {
            ((ObjectNode) node).remove("dataSeries");
        }
        return mapper.writeValueAsString(node);
    }

    private String agentId(Args args) throws ToolException {
        String agentId = args.string("agentId", "");
        if (central && agentId.isEmpty()) {
            throw new ToolException("agentId is required (use list_agents)");
        }
        return agentId;
    }

    private Params agentRollupParams(Args args) throws ToolException {
        return new Params().put("agent-rollup-id", agentId(args));
    }

    private Params timeRangeParams(Args args) throws ToolException {
        return agentRollupParams(args).put("from", args.from()).put("to", args.to());
    }

    private Params transactionParams(Args args) throws ToolException {
        Params params = timeRangeParams(args)
                .put("transaction-type", args.requiredString("transactionType"));
        String transactionName = args.string("transactionName", "");
        if (!transactionName.isEmpty()) {
            params.put("transaction-name", transactionName);
        }
        return params;
    }

    private Params traceParams(Args args) throws ToolException {
        String agentId = agentId(args);
        if (agentId.endsWith("::")) {
            throw new ToolException("agentId must be the id of the agent that captured the trace"
                    + " (as returned by list_traces), not an agent rollup id");
        }
        return new Params().put("agent-id", agentId)
                .put("trace-id", args.requiredString("traceId"))
                .put("check-live-traces", true);
    }

    private SchemaBuilder schema() {
        return new SchemaBuilder();
    }

    private static ObjectNode result(JsonNode id, JsonNode result) {
        ObjectNode response = JsonNodeFactory.instance.objectNode();
        response.put("jsonrpc", "2.0");
        response.set("id", id);
        response.set("result", result);
        return response;
    }

    private static ObjectNode error(@Nullable JsonNode id, int code, @Nullable String message) {
        ObjectNode response = JsonNodeFactory.instance.objectNode();
        response.put("jsonrpc", "2.0");
        if (id == null) {
            response.putNull("id");
        } else {
            response.set("id", id);
        }
        ObjectNode error = response.putObject("error");
        error.put("code", code);
        error.put("message", Strings.nullToEmpty(message));
        return response;
    }

    private static CommonResponse jsonResponse(HttpResponseStatus status, JsonNode node)
            throws Exception {
        return new CommonResponse(status, MediaType.JSON_UTF_8, mapper.writeValueAsString(node));
    }

    private class Backend {

        private final CommonHandler commonHandler;
        private final Authentication authentication;

        private Backend(CommonHandler commonHandler, Authentication authentication) {
            this.commonHandler = commonHandler;
            this.authentication = authentication;
        }

        private String get(String path, Params params) throws Exception {
            CommonResponse response =
                    commonHandler.handleInternalGet(path, params.map, authentication);
            String content = contentAsString(response.getContent());
            HttpResponseStatus status = response.getStatus();
            if (status.equals(HttpResponseStatus.OK)) {
                return content;
            }
            if (status.equals(HttpResponseStatus.UNAUTHORIZED)
                    || status.equals(HttpResponseStatus.FORBIDDEN)) {
                throw new ToolException("User \"" + authentication.caseAmbiguousUsername()
                        + "\" is not permitted to access this data");
            }
            if (status.equals(HttpResponseStatus.NOT_FOUND)) {
                throw new ToolException("Not found (or no data)");
            }
            String message = content;
            try {
                JsonNode node = mapper.readTree(content);
                if (node != null && node.hasNonNull("message")) {
                    message = node.get("message").asText();
                }
            } catch (Exception e) {
                logger.debug(e.getMessage(), e);
            }
            throw new ToolException(status.code() + " " + status.reasonPhrase() + ": " + message);
        }
    }

    private static String contentAsString(Object content) throws Exception {
        if (content instanceof String) {
            return (String) content;
        }
        if (content instanceof ByteBuf) {
            return ((ByteBuf) content).toString(UTF_8);
        }
        if (content instanceof ChunkSource) {
            StringWriter writer = new StringWriter();
            ChunkCopier copier = ((ChunkSource) content).getCopier(writer);
            while (copier.copyNext()) {
                // keep copying until everything is in the writer
            }
            return writer.toString();
        }
        throw new IllegalStateException("Unexpected content: " + content.getClass().getName());
    }

    private class Args {

        private final JsonNode node;

        private Args(JsonNode node) {
            this.node = node;
        }

        private long from() throws ToolException {
            Long from = longValue("from");
            return from == null ? to() - DEFAULT_TIME_RANGE_MILLIS : from;
        }

        private long to() throws ToolException {
            Long to = longValue("to");
            return to == null ? clock.currentTimeMillis() : to;
        }

        private String requiredString(String name) throws ToolException {
            String value = string(name, "");
            if (value.isEmpty()) {
                throw new ToolException(name + " is required");
            }
            return value;
        }

        private String string(String name, String defaultValue) {
            JsonNode value = node.get(name);
            return value == null || value.isNull() ? defaultValue : value.asText();
        }

        private boolean bool(String name, boolean defaultValue) {
            JsonNode value = node.get(name);
            return value == null || value.isNull() ? defaultValue : value.asBoolean();
        }

        private int integer(String name, int defaultValue) throws ToolException {
            Long value = longValue(name);
            return value == null ? defaultValue : value.intValue();
        }

        private @Nullable Long longValue(String name) throws ToolException {
            Double value = number(name);
            return value == null ? null : value.longValue();
        }

        private @Nullable Double number(String name) throws ToolException {
            JsonNode value = node.get(name);
            if (value == null || value.isNull()) {
                return null;
            }
            if (value.isNumber()) {
                return value.asDouble();
            }
            try {
                return Double.parseDouble(value.asText());
            } catch (NumberFormatException e) {
                throw new ToolException(name + " must be a number");
            }
        }

        private List<String> stringList(String name) {
            JsonNode value = node.get(name);
            List<String> list = Lists.newArrayList();
            if (value == null || value.isNull()) {
                return list;
            }
            if (value.isArray()) {
                for (JsonNode element : value) {
                    list.add(element.asText());
                }
            } else {
                list.add(value.asText());
            }
            return list;
        }
    }

    private static class Params {

        private final Map<String, List<String>> map = new LinkedHashMap<String, List<String>>();

        private Params put(String name, Object value) {
            map.put(name, Lists.newArrayList(String.valueOf(value)));
            return this;
        }

        private Params putAll(String name, List<String> values) {
            map.put(name, Lists.newArrayList(values));
            return this;
        }
    }

    private class SchemaBuilder {

        private final ObjectNode schema = mapper.createObjectNode();
        private final ObjectNode properties;
        private final ArrayNode required;

        private SchemaBuilder() {
            schema.put("type", "object");
            properties = schema.putObject("properties");
            required = mapper.createArrayNode();
        }

        private SchemaBuilder agentId() {
            return stringProperty("agentId", central
                    ? "Agent or agent rollup id, as returned by list_agents"
                    : "Agent id (can be omitted in embedded mode)", central);
        }

        private SchemaBuilder traceAgentId() {
            return stringProperty("agentId", central
                    ? "Id of the agent that captured the trace, as returned by list_traces"
                    : "Agent id (can be omitted in embedded mode)", central);
        }

        private SchemaBuilder traceId() {
            return stringProperty("traceId", "Trace id, as returned by list_traces", true);
        }

        private SchemaBuilder transactionType() {
            return stringProperty("transactionType",
                    "Transaction type, as returned by list_transaction_types (e.g. Web)", true);
        }

        private SchemaBuilder transactionName() {
            return stringProperty("transactionName",
                    "Transaction name (omit for all transactions of the type)", false);
        }

        private SchemaBuilder timeRange() {
            numberProperty("from", "Start of the time range, epoch milliseconds"
                    + " (default: 60 minutes before to)");
            return numberProperty("to", "End of the time range, epoch milliseconds"
                    + " (default: now)");
        }

        private SchemaBuilder includeChartSeries() {
            return booleanProperty("includeChartSeries",
                    "Include the chart data series (verbose, default false)");
        }

        private SchemaBuilder stringProperty(String name, String description,
                boolean isRequired) {
            property(name, "string", description);
            if (isRequired) {
                required.add(name);
            }
            return this;
        }

        private SchemaBuilder enumProperty(String name, String description, String... values) {
            ArrayNode enumNode = property(name, "string", description).putArray("enum");
            for (String value : values) {
                enumNode.add(value);
            }
            return this;
        }

        private SchemaBuilder intProperty(String name, String description) {
            property(name, "integer", description);
            return this;
        }

        private SchemaBuilder numberProperty(String name, String description) {
            property(name, "number", description);
            return this;
        }

        private SchemaBuilder booleanProperty(String name, String description) {
            property(name, "boolean", description);
            return this;
        }

        private SchemaBuilder numberArrayProperty(String name, String description) {
            property(name, "array", description).putObject("items").put("type", "number");
            return this;
        }

        private SchemaBuilder stringArrayProperty(String name, String description,
                boolean isRequired) {
            property(name, "array", description).putObject("items").put("type", "string");
            if (isRequired) {
                required.add(name);
            }
            return this;
        }

        private ObjectNode property(String name, String type, String description) {
            ObjectNode property = properties.putObject(name);
            property.put("type", type);
            property.put("description", description);
            return property;
        }

        private ObjectNode build() {
            if (required.size() > 0) {
                schema.set("required", required);
            }
            return schema;
        }
    }

    private static class Tool {

        private final String name;
        private final String description;
        private final ObjectNode inputSchema;
        private final ToolHandler handler;

        private Tool(String name, String description, SchemaBuilder inputSchema,
                ToolHandler handler) {
            this.name = name;
            this.description = description;
            this.inputSchema = inputSchema.build();
            this.handler = handler;
        }
    }

    private interface ToolHandler {
        String call(Args args, Backend backend) throws Exception;
    }

    // expected errors, reported to the mcp client as tool errors (isError=true)
    @SuppressWarnings("serial")
    private static class ToolException extends Exception {

        private ToolException(String message) {
            super(message);
        }
    }
}
