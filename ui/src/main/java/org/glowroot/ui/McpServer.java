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
import java.net.URLEncoder;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
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
// Tools cover transactions, traces and jvm gauges (read), plus slow trace threshold, gauge and
// instrumentation configuration (write). Every tool call is dispatched to the same http/json
// services that back the UI, so the existing permission model applies unchanged (e.g. config
// changes require agent:config:edit:* permissions).
//
// Tool results include glowrootUrl links into the UI, so that mcp clients can point their users to
// the corresponding chart, trace or configuration page.
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

    private static final String INSTRUCTIONS = "Access to Glowroot APM data and configuration."
            + " Start with list_agents (central) to get an agentId (embedded mode has a single"
            + " agent, agentId can be omitted), then list_transaction_types. Times are epoch"
            + " milliseconds; from/to default to the last 60 minutes. Durations from aggregates"
            + " are in nanoseconds unless the field name says otherwise. Results contain"
            + " glowrootUrl links to the Glowroot UI: share them with the user as evidence."
            + " Configuration changes (slow trace threshold, gauges, instrumentation) take"
            + " effect on the monitored JVM; new or changed instrumentation only applies to"
            + " already loaded classes after apply_instrumentation_changes.";

    private final boolean central;
    private final boolean offlineViewer;
    private final String version;
    private final HttpSessionManager httpSessionManager;
    private final Supplier<Boolean> https;
    private final Clock clock;

    private final ImmutableList<Tool> tools;

    McpServer(boolean central, boolean offlineViewer, String version,
            HttpSessionManager httpSessionManager, Supplier<Boolean> https, Clock clock) {
        this.central = central;
        this.offlineViewer = offlineViewer;
        this.version = version;
        this.httpSessionManager = httpSessionManager;
        this.https = https;
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
        Backend backend = new Backend(commonHandler, authentication, getUiBaseUrl(request));
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

    // base url of the glowroot UI as seen by the mcp client (honoring reverse proxy headers)
    private String getUiBaseUrl(CommonRequest request) {
        String scheme = firstHeaderValue(request, "X-Forwarded-Proto");
        if (scheme == null) {
            scheme = Boolean.TRUE.equals(https.get()) ? "https" : "http";
        }
        String host = firstHeaderValue(request, "X-Forwarded-Host");
        if (host == null) {
            host = firstHeaderValue(request, HttpHeaderNames.HOST.toString());
        }
        if (host == null) {
            host = "localhost";
        }
        String contextPath = request.getContextPath();
        if (contextPath.endsWith("/")) {
            contextPath = contextPath.substring(0, contextPath.length() - 1);
        }
        return scheme + "://" + host + contextPath;
    }

    private static @Nullable String firstHeaderValue(CommonRequest request, String name) {
        String value = request.getHeader(name);
        if (value == null) {
            return null;
        }
        int index = value.indexOf(',');
        String first = (index == -1 ? value : value.substring(0, index)).trim();
        return first.isEmpty() ? null : first;
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
            ObjectNode annotations = toolNode.putObject("annotations");
            annotations.put("readOnlyHint", tool.readOnly);
            if (!tool.readOnly) {
                annotations.put("destructiveHint", tool.destructive);
                annotations.put("openWorldHint", false);
            }
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
                (args, backend) -> withUrl(backend.get("/backend/transaction/summaries",
                        timeRangeParams(args)
                                .put("transaction-type", args.requiredString("transactionType"))
                                .put("sort-order", args.string("sortOrder", "total-time"))
                                .put("limit", args.integer("limit", 20))),
                        "", backend.uiUrl("transaction/average", uiTransactionParams(args)))));

        list.add(new Tool("get_transaction_overview",
                "Response time breakdown (merged timer tree, average duration, transaction count)"
                        + " for a transaction type, or a single transaction name.",
                schema().agentId().transactionType().transactionName().timeRange()
                        .includeChartSeries(),
                (args, backend) -> withUrl(stripChartSeries(args,
                        backend.get("/backend/transaction/average", transactionParams(args))),
                        "", backend.uiUrl("transaction/average", uiTransactionParams(args)))));

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
                    return withUrl(stripChartSeries(args,
                            backend.get("/backend/transaction/percentiles",
                                    transactionParams(args).putAll("percentile", percentiles))),
                            "", backend.uiUrl("transaction/percentiles",
                                    uiTransactionParams(args)));
                }));

        list.add(new Tool("get_transaction_throughput",
                "Throughput (transaction count and transactions per minute) for a transaction type"
                        + " or name.",
                schema().agentId().transactionType().transactionName().timeRange()
                        .includeChartSeries(),
                (args, backend) -> withUrl(stripChartSeries(args,
                        backend.get("/backend/transaction/throughput", transactionParams(args))),
                        "", backend.uiUrl("transaction/throughput", uiTransactionParams(args)))));

        list.add(new Tool("get_transaction_queries",
                "Queries (SQL, CQL, ...) executed by a transaction type or name, sorted by total"
                        + " time. Use get_full_query_text with fullQueryTextSha1 when the text"
                        + " is truncated.",
                schema().agentId().transactionType().transactionName().timeRange(),
                (args, backend) -> withUrl(backend.get("/backend/transaction/queries",
                        transactionParams(args)), "queries",
                        backend.uiUrl("transaction/queries", uiTransactionParams(args)))));

        list.add(new Tool("get_full_query_text",
                "Full text of a truncated query returned by get_transaction_queries or"
                        + " get_trace_queries.",
                schema().agentId().stringProperty("fullQueryTextSha1",
                        "The fullQueryTextSha1 value of the query", true),
                (args, backend) -> backend.get("/backend/transaction/full-query-text",
                        agentRollupParams(args).put("full-text-sha1",
                                args.requiredString("fullQueryTextSha1")))));

        list.add(new Tool("get_transaction_service_calls",
                "Service calls (outgoing http, ...) made by a transaction type or name, sorted by"
                        + " total time.",
                schema().agentId().transactionType().transactionName().timeRange(),
                (args, backend) -> withUrl(backend.get("/backend/transaction/service-calls",
                        transactionParams(args)), "serviceCalls",
                        backend.uiUrl("transaction/service-calls", uiTransactionParams(args)))));

        list.add(new Tool("list_traces",
                "List captured traces (slow traces, or error traces when errorsOnly is true) for a"
                        + " transaction type or name. Returns traceId and agentId to use with"
                        + " get_trace, and a glowrootUrl per trace opening it in the UI.",
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
                (args, backend) -> {
                    String header = backend.get("/backend/trace/header", traceParams(args));
                    return withUrl(header, "", traceUrl(args, backend, header));
                }));

        list.add(new Tool("get_trace_entries",
                "Trace entries (timeline of instrumented calls) of a trace. Query entries carry an"
                        + " abbreviated queryText, use get_trace_queries for the full text.",
                schema().traceAgentId().traceId(),
                (args, backend) -> withUrl(inlineSharedQueryTexts(
                        backend.get("/backend/trace/entries", traceParams(args)), true),
                        "", traceUrl(args, backend))));

        list.add(new Tool("get_trace_queries",
                "Queries executed during a trace, aggregated by query text and sorted by total"
                        + " time (executionCount helps spotting N+1 patterns). When Glowroot"
                        + " truncated the text, use get_full_query_text with fullQueryTextSha1.",
                schema().traceAgentId().traceId(),
                (args, backend) -> withUrl(sortQueriesByTotalTime(inlineSharedQueryTexts(
                        backend.get("/backend/trace/queries", traceParams(args)), false)),
                        "", traceUrl(args, backend))));

        // ---- jvm gauges ----

        list.add(new Tool("list_gauges",
                "List the JVM gauges (MBean attributes such as heap usage, CPU load, thread count)"
                        + " that have values in the time range.",
                schema().agentId().timeRange(),
                (args, backend) -> {
                    JsonNode node = mapper.readTree(
                            backend.get("/backend/jvm/gauges", timeRangeParams(args)));
                    return withUrl(mapper.writeValueAsString(node.path("allGauges")), "gauges",
                            backend.uiUrl("jvm/gauges", uiAgentParams(agentId(args))
                                    .put("from", args.from()).put("to", args.to())));
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
                    node.put("glowrootUrl", gaugesUiUrl(args, backend, gaugeNames));
                    return mapper.writeValueAsString(node);
                }));

        // ---- configuration: slow trace threshold ----

        list.add(new Tool("get_transaction_config",
                "Transaction configuration of an agent: slow trace threshold (traces slower than"
                        + " this are captured), per transaction type/name/user threshold"
                        + " overrides, profiling interval.",
                schema().agentId(),
                (args, backend) -> withUrl(backend.get("/backend/config/transaction",
                        agentIdParams(args)), "",
                        backend.uiUrl("config/transaction", uiAgentParams(agentId(args))))));

        list.add(Tool.write("set_slow_trace_threshold",
                "Set the slow trace threshold in milliseconds. Without transactionType this sets"
                        + " the agent default; with transactionType (and optionally"
                        + " transactionName and/or user) it adds or updates a threshold override"
                        + " (removeOverride=true removes it). Lower values capture more traces.",
                schema().agentId()
                        .intProperty("thresholdMillis", "Slow trace threshold in milliseconds"
                                + " (required unless removeOverride is true)")
                        .stringProperty("transactionType",
                                "Transaction type of the override", false)
                        .stringProperty("transactionName",
                                "Transaction name of the override (optional)", false)
                        .stringProperty("user", "User of the override (optional)", false)
                        .booleanProperty("removeOverride",
                                "Remove the matching override instead of setting it"),
                (args, backend) -> setSlowTraceThreshold(args, backend)));

        // ---- configuration: gauges ----

        list.add(new Tool("list_gauge_configs",
                "List the configured gauges (MBean object name and attributes) of an agent, with"
                        + " the version needed by delete_gauge.",
                schema().agentId(),
                (args, backend) -> listGaugeConfigs(args, backend)));

        list.add(new Tool("search_mbeans",
                "Search the MBean object names of the running JVM (e.g. \"java.lang:type=\" or"
                        + " \"Catalina:type=ThreadPool\"), to find what can be added as a gauge."
                        + " The agent must be connected.",
                schema().agentId()
                        .stringProperty("partialObjectName",
                                "Part of the MBean object name to search for", true)
                        .intProperty("limit", "Max number of results (default 20)"),
                (args, backend) -> withUrl(backend.get("/backend/config/matching-mbean-objects",
                        agentIdParams(args)
                                .put("partial-object-name",
                                        args.requiredString("partialObjectName"))
                                .put("limit", args.integer("limit", 20))),
                        "objectNames", null)));

        list.add(new Tool("get_mbean_attributes",
                "Numeric attributes of an MBean that can be captured as gauges (composite"
                        + " attributes are listed as attribute.key). Also tells whether a gauge"
                        + " already exists for this MBean.",
                schema().agentId()
                        .stringProperty("objectName", "MBean object name (patterns with * are"
                                + " allowed)", true),
                (args, backend) -> backend.get("/backend/config/mbean-attributes",
                        agentIdParams(args).put("object-name",
                                args.requiredString("objectName")))));

        list.add(Tool.write("create_gauge",
                "Create a gauge: Glowroot then periodically captures the given numeric MBean"
                        + " attributes (default every 5 seconds). Counter attributes (ever"
                        + " increasing totals) are captured as a rate per second. Values show up"
                        + " in get_gauge_values after the next collections.",
                schema().agentId()
                        .stringProperty("mbeanObjectName", "MBean object name, e.g."
                                + " Catalina:type=ThreadPool,name=\"http-nio-8080\"", true)
                        .stringArrayProperty("attributes",
                                "Attribute names, as returned by get_mbean_attributes", true)
                        .stringArrayProperty("counterAttributes", "Subset of attributes that"
                                + " are counters (captured as a rate per second)", false),
                (args, backend) -> createGauge(args, backend)));

        list.add(Tool.delete("delete_gauge",
                "Delete a configured gauge (version from list_gauge_configs). Already captured"
                        + " values are kept until they expire.",
                schema().agentId().stringProperty("version", "Gauge config version", true),
                (args, backend) -> {
                    backend.post("/backend/config/gauges/remove", agentIdParams(args),
                            objectNode("version", args.requiredString("version")));
                    return withUrl("{\"deleted\":true}", "", backend.uiUrl("config/gauge-list",
                            uiAgentParams(agentId(args))));
                }));

        // ---- configuration: instrumentation ----

        list.add(new Tool("list_instrumentations",
                "List the custom instrumentation configs of an agent. jvmOutOfSync=true means"
                        + " some changes are not applied to already loaded classes yet (see"
                        + " apply_instrumentation_changes).",
                schema().agentId(),
                (args, backend) -> listInstrumentations(args, backend)));

        list.add(new Tool("search_classes",
                "Search class names loaded in (or available to) the monitored JVM, to target an"
                        + " instrumentation. The agent must be connected.",
                schema().agentId()
                        .stringProperty("partialClassName",
                                "Part of the fully qualified class name", true)
                        .intProperty("limit", "Max number of results (default 20)"),
                (args, backend) -> withUrl(backend.get("/backend/config/matching-class-names",
                        agentIdParams(args)
                                .put("partial-class-name", args.requiredString("partialClassName"))
                                .put("limit", args.integer("limit", 20))),
                        "classNames", null)));

        list.add(new Tool("search_methods",
                "Search the method names of a class, to target an instrumentation.",
                schema().agentId()
                        .stringProperty("className", "Fully qualified class name", true)
                        .stringProperty("partialMethodName", "Part of the method name", true)
                        .intProperty("limit", "Max number of results (default 20)"),
                (args, backend) -> withUrl(backend.get("/backend/config/matching-method-names",
                        agentIdParams(args)
                                .put("class-name", args.requiredString("className"))
                                .put("partial-method-name",
                                        args.requiredString("partialMethodName"))
                                .put("limit", args.integer("limit", 20))),
                        "methodNames", null)));

        list.add(new Tool("get_method_signatures",
                "Signatures (parameter types, return type, modifiers) of a method, to restrict an"
                        + " instrumentation to one overload.",
                schema().agentId()
                        .stringProperty("className", "Fully qualified class name", true)
                        .stringProperty("methodName", "Method name", true),
                (args, backend) -> withUrl(backend.get("/backend/config/method-signatures",
                        agentIdParams(args)
                                .put("class-name", args.requiredString("className"))
                                .put("method-name", args.requiredString("methodName"))),
                        "signatures", null)));

        list.add(Tool.write("create_instrumentation",
                "Create a custom instrumentation (pointcut) on a method. captureKind: timer (only"
                        + " time the method in the timer breakdown), trace-entry (also add an"
                        + " entry to traces), transaction (start a new transaction, e.g. for"
                        + " background jobs), other. Message/name templates can use {{0}},"
                        + " {{1}}.. (arguments, e.g. {{0.id}}), {{this}} (e.g."
                        + " {{this.class.simpleName}}), {{_}} (return value) and {{methodName}}."
                        + " Call apply_instrumentation_changes afterwards to apply it to already"
                        + " loaded classes.",
                schema().agentId()
                        .stringProperty("className", "Fully qualified class (or interface)"
                                + " name; methods of subclasses / implementations are matched"
                                + " too", true)
                        .stringProperty("methodName", "Method name (* wildcards allowed)", true)
                        .stringArrayProperty("methodParameterTypes", "Parameter types, e.g."
                                + " [\"java.lang.String\", \"long\"] (default [\"..\"] = any)",
                                false)
                        .stringProperty("methodReturnType", "Return type (default any)", false)
                        .enumProperty("captureKind", "What to capture", "timer", "trace-entry",
                                "transaction", "other")
                        .stringProperty("timerName", "Timer name (default derived from the"
                                + " method)", false)
                        .stringProperty("traceEntryMessageTemplate", "Trace entry message"
                                + " (trace-entry, transaction; default Class.method())", false)
                        .intProperty("traceEntryStackThresholdMillis", "Capture the stack"
                                + " trace of trace entries slower than this (optional)")
                        .stringProperty("transactionType", "Transaction type (transaction"
                                + " only), e.g. Background", false)
                        .stringProperty("transactionNameTemplate", "Transaction name template"
                                + " (transaction only, default Class.method)", false)
                        .stringProperty("transactionUserTemplate", "Transaction user template"
                                + " (transaction only, optional)", false)
                        .intProperty("transactionSlowThresholdMillis", "Slow trace threshold"
                                + " for this transaction (transaction only, optional)")
                        .enumProperty("alreadyInTransactionBehavior", "What to do when the"
                                + " method runs inside an existing transaction (transaction"
                                + " only, default capture-trace-entry)", "capture-trace-entry",
                                "capture-new-transaction", "do-nothing")
                        .stringProperty("nestingGroup", "Nesting group (optional, prevents"
                                + " nested captures of the same group)", false)
                        .intProperty("order", "Order relative to other instrumentation"
                                + " (default 0)"),
                (args, backend) -> createInstrumentation(args, backend)));

        list.add(Tool.delete("delete_instrumentation",
                "Delete custom instrumentation configs (versions from list_instrumentations)."
                        + " Call apply_instrumentation_changes afterwards to remove them from"
                        + " already loaded classes.",
                schema().agentId().stringArrayProperty("versions",
                        "Instrumentation config versions", true),
                (args, backend) -> {
                    List<String> versions = args.stringList("versions");
                    if (versions.isEmpty()) {
                        throw new ToolException("versions is required");
                    }
                    ObjectNode body = mapper.createObjectNode();
                    ArrayNode versionsNode = body.putArray("versions");
                    for (String version : versions) {
                        versionsNode.add(version);
                    }
                    backend.post("/backend/config/instrumentation/remove", agentIdParams(args),
                            body);
                    return withUrl("{\"deleted\":" + versions.size() + "}", "",
                            backend.uiUrl("config/instrumentation-list",
                                    uiAgentParams(agentId(args))));
                }));

        list.add(Tool.write("apply_instrumentation_changes",
                "Apply the instrumentation configuration to the classes already loaded in the"
                        + " monitored JVM (re-weaving them), so that created, changed or deleted"
                        + " instrumentation takes effect without restarting the JVM. Returns the"
                        + " number of re-woven classes.",
                schema().agentId(),
                (args, backend) -> withUrl(backend.post("/backend/config/reweave",
                        agentIdParams(args), mapper.createObjectNode()), "",
                        backend.uiUrl("config/instrumentation-list",
                                uiAgentParams(agentId(args))))));

        return ImmutableList.copyOf(list);
    }

    // ---- trace and gauge links ----

    private @Nullable String traceUrl(Args args, Backend backend) throws Exception {
        try {
            return traceUrl(args, backend,
                    backend.get("/backend/trace/header", traceParams(args)));
        } catch (Exception e) {
            // the link is a convenience, the tool result itself is still useful
            logger.debug(e.getMessage(), e);
            return null;
        }
    }

    // the trace opens as a modal on top of the traces chart of its transaction
    private @Nullable String traceUrl(Args args, Backend backend, String headerJson)
            throws Exception {
        JsonNode header = mapper.readTree(headerJson);
        if (header == null || !header.hasNonNull("transactionType")) {
            // e.g. {"expired":true}
            return null;
        }
        String agentId = requireAgentId(args, "the agent that captured the trace");
        long captureTime = header.path("captureTime").asLong();
        long startTime = header.path("startTime").asLong(captureTime);
        Params params = uiAgentParams(agentId)
                .put("transaction-type", header.path("transactionType").asText())
                .put("transaction-name", header.path("transactionName").asText())
                .put("from", startTime - MINUTES.toMillis(30))
                .put("to", captureTime + MINUTES.toMillis(30));
        return backend.uiUrl("transaction/traces",
                addTraceModalParams(params, agentId, args.requiredString("traceId")));
    }

    private Params addTraceModalParams(Params params, String agentId, String traceId) {
        if (central) {
            params.put("modal-agent-id", agentId);
        }
        return params.put("modal-trace-id", traceId);
    }

    private String gaugesUiUrl(Args args, Backend backend, List<String> gaugeNames)
            throws Exception {
        return backend.uiUrl("jvm/gauges", uiAgentParams(agentId(args))
                .putAll("gauge-name", gaugeNames)
                .put("from", args.from())
                .put("to", args.to()));
    }

    // ---- configuration ----

    private String setSlowTraceThreshold(Args args, Backend backend) throws Exception {
        Params agentIdParams = agentIdParams(args);
        JsonNode current =
                mapper.readTree(backend.get("/backend/config/transaction", agentIdParams));
        JsonNode configNode = current.path("config");
        if (!(configNode instanceof ObjectNode)) {
            throw new ToolException("Unexpected transaction config: " + current);
        }
        ObjectNode config = (ObjectNode) configNode;
        boolean removeOverride = args.bool("removeOverride", false);
        Long thresholdMillis = args.longValue("thresholdMillis");
        if (thresholdMillis == null && !removeOverride) {
            throw new ToolException("thresholdMillis is required");
        }
        if (thresholdMillis != null && thresholdMillis < 0) {
            throw new ToolException("thresholdMillis must be positive");
        }
        String transactionType = args.string("transactionType", "");
        String transactionName = args.string("transactionName", "");
        String user = args.string("user", "");
        String change;
        if (transactionType.isEmpty()) {
            if (!transactionName.isEmpty() || !user.isEmpty() || removeOverride) {
                throw new ToolException("transactionType is required for a threshold override");
            }
            change = "default slow trace threshold: "
                    + config.path("slowThresholdMillis").asInt() + " ms -> " + thresholdMillis
                    + " ms";
            config.put("slowThresholdMillis", thresholdMillis.intValue());
        } else {
            JsonNode overridesNode = config.path("slowThresholdOverrides");
            if (!(overridesNode instanceof ArrayNode)) {
                throw new ToolException("Unexpected transaction config: " + current);
            }
            ArrayNode overrides = (ArrayNode) overridesNode;
            int index = -1;
            for (int i = 0; i < overrides.size(); i++) {
                JsonNode override = overrides.get(i);
                if (override.path("transactionType").asText().equals(transactionType)
                        && override.path("transactionName").asText().equals(transactionName)
                        && override.path("user").asText().equals(user)) {
                    index = i;
                    break;
                }
            }
            String target = "override " + transactionType
                    + (transactionName.isEmpty() ? "" : " / " + transactionName)
                    + (user.isEmpty() ? "" : " / user " + user);
            if (removeOverride) {
                if (index == -1) {
                    throw new ToolException("No matching override: " + target);
                }
                overrides.remove(index);
                change = "removed " + target;
            } else if (index == -1) {
                ObjectNode override = overrides.addObject();
                override.put("transactionType", transactionType);
                override.put("transactionName", transactionName);
                override.put("user", user);
                override.put("thresholdMillis", thresholdMillis.intValue());
                change = "added " + target + ": " + thresholdMillis + " ms";
            } else {
                ObjectNode override = (ObjectNode) overrides.get(index);
                change = target + ": " + override.path("thresholdMillis").asInt() + " ms -> "
                        + thresholdMillis + " ms";
                override.put("thresholdMillis", thresholdMillis.intValue());
            }
        }
        ObjectNode result = (ObjectNode) mapper.readTree(
                backend.post("/backend/config/transaction", agentIdParams, config));
        result.put("change", change);
        result.put("glowrootUrl",
                backend.uiUrl("config/transaction", uiAgentParams(agentId(args))));
        return mapper.writeValueAsString(result);
    }

    private String listGaugeConfigs(Args args, Backend backend) throws Exception {
        String agentId = agentId(args);
        JsonNode responses =
                mapper.readTree(backend.get("/backend/config/gauges", agentIdParams(args)));
        ObjectNode result = mapper.createObjectNode();
        ArrayNode gaugeConfigs = result.putArray("gaugeConfigs");
        for (JsonNode response : responses) {
            JsonNode config = response.path("config");
            if (config instanceof ObjectNode) {
                ObjectNode gaugeConfig = gaugeConfigs.addObject();
                gaugeConfig.setAll((ObjectNode) config);
                gaugeConfig.put("glowrootUrl", backend.uiUrl("config/gauge",
                        uiAgentParams(agentId).put("v", config.path("version").asText())));
            }
        }
        result.put("glowrootUrl", backend.uiUrl("config/gauge-list", uiAgentParams(agentId)));
        return mapper.writeValueAsString(result);
    }

    private String createGauge(Args args, Backend backend) throws Exception {
        String mbeanObjectName = args.requiredString("mbeanObjectName");
        List<String> attributes = args.stringList("attributes");
        if (attributes.isEmpty()) {
            throw new ToolException("attributes is required");
        }
        List<String> counterAttributes = args.stringList("counterAttributes");
        for (String counterAttribute : counterAttributes) {
            if (!attributes.contains(counterAttribute)) {
                throw new ToolException("counterAttributes must be a subset of attributes: "
                        + counterAttribute);
            }
        }
        ObjectNode body = mapper.createObjectNode();
        body.put("mbeanObjectName", mbeanObjectName);
        ArrayNode mbeanAttributes = body.putArray("mbeanAttributes");
        List<String> gaugeNames = Lists.newArrayList();
        for (String attribute : attributes) {
            boolean counter = counterAttributes.contains(attribute);
            ObjectNode mbeanAttribute = mbeanAttributes.addObject();
            mbeanAttribute.put("name", attribute);
            mbeanAttribute.put("counter", counter);
            // same naming as GaugeCollector
            gaugeNames.add(mbeanObjectName + ":" + attribute + (counter ? "[counter]" : ""));
        }
        String response;
        try {
            response = backend.post("/backend/config/gauges/add", agentIdParams(args), body);
        } catch (ToolException e) {
            if (e.getMessage().startsWith("409")) {
                throw new ToolException("A gauge already exists for this MBean object name (use"
                        + " list_gauge_configs)");
            }
            throw e;
        }
        ObjectNode result = (ObjectNode) mapper.readTree(response);
        String agentId = agentId(args);
        result.put("glowrootUrl", backend.uiUrl("config/gauge",
                uiAgentParams(agentId).put("v", result.at("/config/version").asText())));
        if (mbeanObjectName.indexOf('*') == -1 && mbeanObjectName.indexOf('?') == -1) {
            // with a pattern, gauge names depend on the matching MBeans
            ArrayNode gaugeNamesNode = result.putArray("gaugeNames");
            for (String gaugeName : gaugeNames) {
                gaugeNamesNode.add(gaugeName);
            }
            result.put("gaugeValuesUrl", gaugesUiUrl(args, backend, gaugeNames));
        }
        return mapper.writeValueAsString(result);
    }

    private String listInstrumentations(Args args, Backend backend) throws Exception {
        String agentId = agentId(args);
        JsonNode node = mapper.readTree(
                backend.get("/backend/config/instrumentation", agentIdParams(args)));
        if (!(node instanceof ObjectNode)) {
            return mapper.writeValueAsString(node);
        }
        ObjectNode result = (ObjectNode) node;
        for (JsonNode config : result.path("configs")) {
            if (config instanceof ObjectNode) {
                ((ObjectNode) config).put("glowrootUrl", backend.uiUrl("config/instrumentation",
                        uiAgentParams(agentId).put("v", config.path("version").asText())));
            }
        }
        result.put("glowrootUrl",
                backend.uiUrl("config/instrumentation-list", uiAgentParams(agentId)));
        return mapper.writeValueAsString(result);
    }

    private String createInstrumentation(Args args, Backend backend) throws Exception {
        String className = args.requiredString("className");
        String methodName = args.requiredString("methodName");
        String captureKind = args.requiredString("captureKind");
        boolean transaction = captureKind.equals("transaction");
        boolean traceEntry = transaction || captureKind.equals("trace-entry");
        boolean timer = traceEntry || captureKind.equals("timer");
        if (!timer && !captureKind.equals("other")) {
            throw new ToolException("captureKind must be one of timer, trace-entry, transaction,"
                    + " other");
        }
        String simpleClassName = className.substring(
                Math.max(className.lastIndexOf('.'), className.lastIndexOf('$')) + 1);
        List<String> parameterTypes = args.stringList("methodParameterTypes");
        if (parameterTypes.isEmpty()) {
            parameterTypes.add("..");
        }
        // same defaults as a new instrumentation in the UI
        ObjectNode body = mapper.createObjectNode();
        body.put("className", className);
        body.put("classAnnotation", "");
        body.put("subTypeRestriction", "");
        body.put("superTypeRestriction", "");
        body.put("methodName", methodName);
        body.put("methodAnnotation", "");
        ArrayNode parameterTypesNode = body.putArray("methodParameterTypes");
        for (String parameterType : parameterTypes) {
            parameterTypesNode.add(parameterType);
        }
        body.put("methodReturnType", args.string("methodReturnType", ""));
        body.putArray("methodModifiers");
        body.put("nestingGroup", args.string("nestingGroup", ""));
        body.put("order", args.integer("order", 0));
        body.put("captureKind", captureKind);
        body.put("timerName", timer
                ? args.string("timerName", simpleClassName + "." + methodName) : "");
        body.put("traceEntryMessageTemplate", traceEntry ? args.string(
                "traceEntryMessageTemplate", simpleClassName + ".{{methodName}}()") : "");
        Long stackThresholdMillis = args.longValue("traceEntryStackThresholdMillis");
        if (traceEntry && stackThresholdMillis != null) {
            body.put("traceEntryStackThresholdMillis", stackThresholdMillis.intValue());
        } else {
            body.putNull("traceEntryStackThresholdMillis");
        }
        body.put("traceEntryCaptureSelfNested", false);
        if (transaction) {
            body.put("transactionType", args.requiredString("transactionType"));
            body.put("transactionNameTemplate", args.string("transactionNameTemplate",
                    simpleClassName + ".{{methodName}}"));
            body.put("transactionUserTemplate", args.string("transactionUserTemplate", ""));
            body.put("alreadyInTransactionBehavior",
                    args.string("alreadyInTransactionBehavior", "capture-trace-entry"));
        } else {
            body.put("transactionType", "");
            body.put("transactionNameTemplate", "");
            body.put("transactionUserTemplate", "");
            body.putNull("alreadyInTransactionBehavior");
        }
        body.putObject("transactionAttributeTemplates");
        Long transactionSlowThresholdMillis = args.longValue("transactionSlowThresholdMillis");
        if (transaction && transactionSlowThresholdMillis != null) {
            body.put("transactionSlowThresholdMillis", transactionSlowThresholdMillis.intValue());
        } else {
            body.putNull("transactionSlowThresholdMillis");
        }
        body.put("transactionOuter", false);
        body.put("enabledProperty", "");
        body.put("traceEntryEnabledProperty", "");
        ObjectNode result = (ObjectNode) mapper.readTree(backend.post(
                "/backend/config/instrumentation/add", agentIdParams(args), body));
        result.put("glowrootUrl", backend.uiUrl("config/instrumentation",
                uiAgentParams(agentId(args)).put("v", result.at("/config/version").asText())));
        result.put("nextStep", "call apply_instrumentation_changes to apply it to already"
                + " loaded classes");
        return mapper.writeValueAsString(result);
    }

    private static ObjectNode objectNode(String name, String value) {
        ObjectNode node = mapper.createObjectNode();
        node.put(name, value);
        return node;
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
        boolean errorsOnly = args.bool("errorsOnly", false);
        String path = errorsOnly ? "/backend/error/points" : "/backend/transaction/points";
        String uiPath = errorsOnly ? "error/traces" : "transaction/traces";
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
        for (JsonNode trace : traces) {
            ((ObjectNode) trace).put("glowrootUrl", backend.uiUrl(uiPath,
                    addTraceModalParams(uiTransactionParams(args),
                            trace.path("agentId").asText(), trace.path("traceId").asText())));
        }
        result.put("glowrootUrl", backend.uiUrl(uiPath, uiTransactionParams(args)));
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

    // trace entries and trace queries reference their query text by index into a trailing
    // sharedQueryTexts table, which is impractical for mcp clients, so resolve the text in place
    // (note: no JsonNode variable is re-assigned with another node type here, see callTool())
    private static String inlineSharedQueryTexts(String json, boolean abbreviate)
            throws Exception {
        JsonNode node = mapper.readTree(json);
        if (!(node instanceof ObjectNode)) {
            return json;
        }
        JsonNode sharedQueryTexts = ((ObjectNode) node).remove("sharedQueryTexts");
        if (sharedQueryTexts == null) {
            return json;
        }
        inlineSharedQueryTexts(node, sharedQueryTexts, abbreviate);
        return mapper.writeValueAsString(node);
    }

    private static void inlineSharedQueryTexts(JsonNode node, JsonNode sharedQueryTexts,
            boolean abbreviate) {
        if (node.isArray()) {
            for (JsonNode element : node) {
                inlineSharedQueryTexts(element, sharedQueryTexts, abbreviate);
            }
            return;
        }
        if (!(node instanceof ObjectNode)) {
            return;
        }
        ObjectNode objectNode = (ObjectNode) node;
        JsonNode index = objectNode.remove("sharedQueryTextIndex");
        if (index != null) {
            setQueryText(objectNode, sharedQueryTexts.path(index.asInt()), abbreviate);
        }
        for (JsonNode child : objectNode) {
            inlineSharedQueryTexts(child, sharedQueryTexts, abbreviate);
        }
    }

    private static void setQueryText(ObjectNode objectNode, JsonNode sharedQueryText,
            boolean abbreviate) {
        JsonNode fullText = sharedQueryText.get("fullText");
        if (fullText != null) {
            String text = fullText.asText();
            objectNode.put("queryText", abbreviate ? abbreviateQueryText(text) : text);
            return;
        }
        // glowroot only kept the beginning and the end of long query texts in the trace
        objectNode.put("queryText", sharedQueryText.path("truncatedText").asText() + " ... "
                + sharedQueryText.path("truncatedEndText").asText());
        objectNode.put("fullQueryTextSha1", sharedQueryText.path("fullTextSha1").asText());
    }

    private static String abbreviateQueryText(String text) {
        if (text.length() <= 300) {
            return text;
        }
        return text.substring(0, 120) + " ... " + text.substring(text.length() - 120);
    }

    private static String sortQueriesByTotalTime(String json) throws Exception {
        JsonNode node = mapper.readTree(json);
        JsonNode queriesNode = node.path("queries");
        if (!(queriesNode instanceof ArrayNode)) {
            return json;
        }
        ArrayNode queries = (ArrayNode) queriesNode;
        List<JsonNode> sorted = Lists.newArrayList(queries);
        Collections.sort(sorted, (left, right) -> Double.compare(
                right.path("totalDurationNanos").asDouble(),
                left.path("totalDurationNanos").asDouble()));
        queries.removeAll();
        queries.addAll(sorted);
        return mapper.writeValueAsString(node);
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

    // adds the glowrootUrl link to a json object response, or wraps a json array response
    private static String withUrl(String json, String arrayFieldName, @Nullable String url)
            throws Exception {
        JsonNode node = mapper.readTree(json);
        ObjectNode result;
        if (node instanceof ObjectNode) {
            result = (ObjectNode) node;
        } else {
            result = mapper.createObjectNode();
            result.set(arrayFieldName, node);
        }
        if (url != null) {
            result.put("glowrootUrl", url);
        }
        return mapper.writeValueAsString(result);
    }

    // agent selection in UI urls (absent in embedded mode)
    private Params uiAgentParams(String agentId) {
        Params params = new Params();
        if (central && !agentId.isEmpty()) {
            params.put(agentId.endsWith("::") ? "agent-rollup-id" : "agent-id", agentId);
        }
        return params;
    }

    private Params uiTransactionParams(Args args) throws ToolException {
        Params params = uiAgentParams(agentId(args))
                .put("transaction-type", args.requiredString("transactionType"));
        String transactionName = args.string("transactionName", "");
        if (!transactionName.isEmpty()) {
            params.put("transaction-name", transactionName);
        }
        return params.put("from", args.from()).put("to", args.to());
    }

    // agent id (not agent rollup id) for config and trace services that bind agent-id
    private String requireAgentId(Args args, String what) throws ToolException {
        String agentId = agentId(args);
        if (agentId.endsWith("::")) {
            throw new ToolException("agentId must be the id of an agent (" + what + "), not an"
                    + " agent rollup id");
        }
        return agentId;
    }

    private Params agentIdParams(Args args) throws ToolException {
        return new Params().put("agent-id",
                requireAgentId(args, "configuration is per agent"));
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
        String agentId =
                requireAgentId(args, "the agent that captured the trace, see list_traces");
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
        private final String uiBaseUrl;

        private Backend(CommonHandler commonHandler, Authentication authentication,
                String uiBaseUrl) {
            this.commonHandler = commonHandler;
            this.authentication = authentication;
            this.uiBaseUrl = uiBaseUrl;
        }

        private String get(String path, Params params) throws Exception {
            return check(commonHandler.handleInternalGet(path, params.map, authentication));
        }

        // same as the UI: the json body goes to the json service, agent-id stays in the query
        private String post(String path, Params params, JsonNode body) throws Exception {
            return check(commonHandler.handleInternalPost(path, params.map,
                    mapper.writeValueAsString(body), authentication));
        }

        // path is relative to the UI root, e.g. "transaction/average"
        private String uiUrl(String path, Params params) throws Exception {
            StringBuilder sb = new StringBuilder(uiBaseUrl).append('/').append(path);
            char separator = '?';
            for (Map.Entry<String, List<String>> entry : params.map.entrySet()) {
                for (String value : entry.getValue()) {
                    sb.append(separator).append(entry.getKey()).append('=')
                            .append(URLEncoder.encode(value, "UTF-8").replace("+", "%20"));
                    separator = '&';
                }
            }
            return sb.toString();
        }

        private String check(CommonResponse response) throws Exception {
            String content = contentAsString(response.getContent());
            HttpResponseStatus status = response.getStatus();
            if (status.equals(HttpResponseStatus.OK)) {
                return content;
            }
            if (status.equals(HttpResponseStatus.UNAUTHORIZED)
                    || status.equals(HttpResponseStatus.FORBIDDEN)) {
                throw new ToolException("User \"" + authentication.caseAmbiguousUsername()
                        + "\" is not permitted to access this data or to perform this change");
            }
            if (status.equals(HttpResponseStatus.NOT_FOUND)) {
                throw new ToolException("Not found (or no data)");
            }
            if (status.equals(HttpResponseStatus.PRECONDITION_FAILED)) {
                throw new ToolException("The configuration was modified concurrently, read it"
                        + " again and retry");
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
        private final boolean readOnly;
        private final boolean destructive;

        private Tool(String name, String description, SchemaBuilder inputSchema,
                ToolHandler handler) {
            this(name, description, inputSchema, handler, true, false);
        }

        private Tool(String name, String description, SchemaBuilder inputSchema,
                ToolHandler handler, boolean readOnly, boolean destructive) {
            this.name = name;
            this.description = description;
            this.inputSchema = inputSchema.build();
            this.handler = handler;
            this.readOnly = readOnly;
            this.destructive = destructive;
        }

        private static Tool write(String name, String description, SchemaBuilder inputSchema,
                ToolHandler handler) {
            return new Tool(name, description, inputSchema, handler, false, false);
        }

        private static Tool delete(String name, String description, SchemaBuilder inputSchema,
                ToolHandler handler) {
            return new Tool(name, description, inputSchema, handler, false, true);
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
