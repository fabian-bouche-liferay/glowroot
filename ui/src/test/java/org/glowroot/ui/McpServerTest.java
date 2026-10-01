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

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;
import com.google.common.net.MediaType;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.glowroot.common.util.Clock;
import org.glowroot.common2.repo.ConfigRepository;
import org.glowroot.ui.CommonHandler.CommonRequest;
import org.glowroot.ui.CommonHandler.CommonResponse;
import org.glowroot.ui.HttpSessionManager.Authentication;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class McpServerTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    private static final long NOW = 1_000_000_000L;
    private static final long NOW_ROUNDED_UP = 1_000_020_000L;

    private HttpSessionManager httpSessionManager;
    private CommonHandler commonHandler;
    private Authentication user;

    @BeforeEach
    public void beforeEach() throws Exception {
        httpSessionManager = mock(HttpSessionManager.class);
        commonHandler = mock(CommonHandler.class);
        user = authentication("alice", false, ImmutableSet.of("viewer"));
        when(httpSessionManager.authenticateBasic("alice", "secret")).thenReturn(user);
        when(httpSessionManager.getAnonymousAuthentication())
                .thenReturn(authentication("anonymous", true, ImmutableSet.<String>of()));
        // default for the lookups the write tools make before writing (validation, existing
        // configs), individual tests stub the endpoints they assert on
        when(commonHandler.handleInternalGet(anyString(), anyMap(), any(Authentication.class)))
                .thenReturn(ok("[]"));
    }

    @Test
    public void shouldInitialize() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
                        + "{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},"
                        + "\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}"),
                commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.OK);
        JsonNode node = json(response);
        assertThat(node.path("id").asInt()).isEqualTo(1);
        assertThat(node.at("/result/protocolVersion").asText()).isEqualTo("2025-03-26");
        assertThat(node.at("/result/serverInfo/name").asText()).isEqualTo("glowroot");
        assertThat(node.at("/result/serverInfo/version").asText()).isEqualTo("0.0.1-test");
        assertThat(node.at("/result/capabilities/tools").isObject()).isTrue();
    }

    @Test
    public void shouldFallBackToLatestProtocolVersion() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":"
                        + "{\"protocolVersion\":\"1999-01-01\"}}"),
                commonHandler);

        assertThat(json(response).at("/result/protocolVersion").asText())
                .isEqualTo("2025-06-18");
    }

    @Test
    public void shouldListTools() throws Exception {
        CommonResponse response = embedded().handle(
                post(basic("alice", "secret"),
                        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"),
                commonHandler);

        JsonNode tools = json(response).at("/result/tools");
        List<String> names = ImmutableList.copyOf(tools.findValuesAsText("name"));
        assertThat(names).contains("list_agents", "list_transaction_types",
                "get_transaction_summaries", "get_transaction_overview", "list_traces",
                "get_trace", "list_gauges", "get_gauge_values");
        assertThat(names).contains("set_slow_trace_threshold", "create_gauge",
                "create_instrumentation", "apply_instrumentation_changes");
        for (JsonNode tool : tools) {
            assertThat(tool.at("/annotations/readOnlyHint").isBoolean()).isTrue();
            assertThat(tool.at("/inputSchema/type").asText()).isEqualTo("object");
        }
    }

    @Test
    public void shouldChallengeWhenNoCredentialsAndAnonymousHasNoRole() throws Exception {
        CommonResponse response = embedded().handle(
                post(null, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"), commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().get(HttpHeaderNames.WWW_AUTHENTICATE))
                .startsWith("Basic ");
    }

    @Test
    public void shouldAllowAnonymousWhenAnonymousHasRole() throws Exception {
        when(httpSessionManager.getAnonymousAuthentication())
                .thenReturn(authentication("anonymous", true, ImmutableSet.of("viewer")));

        CommonResponse response = embedded().handle(
                post(null, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"), commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.OK);
    }

    @Test
    public void shouldRejectWrongPassword() throws Exception {
        CommonResponse response = embedded().handle(
                post(basic("alice", "wrong"), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"),
                commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.UNAUTHORIZED);
    }

    @Test
    public void shouldRejectCrossOriginRequest() throws Exception {
        CommonRequest request = post(basic("alice", "secret"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
        when(request.getHeader(HttpHeaderNames.ORIGIN)).thenReturn("http://evil.example");
        when(request.getHeader(HttpHeaderNames.HOST)).thenReturn("localhost:4000");

        CommonResponse response = embedded().handle(request, commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.FORBIDDEN);
    }

    @Test
    public void shouldAcceptSameOriginRequest() throws Exception {
        CommonRequest request = post(basic("alice", "secret"),
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
        when(request.getHeader(HttpHeaderNames.ORIGIN)).thenReturn("http://localhost:4000");
        when(request.getHeader(HttpHeaderNames.HOST)).thenReturn("localhost:4000");

        CommonResponse response = embedded().handle(request, commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.OK);
    }

    @Test
    public void shouldNotAllowGet() throws Exception {
        CommonRequest request = mock(CommonRequest.class);
        when(request.getMethod()).thenReturn("GET");

        CommonResponse response = embedded().handle(request, commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.METHOD_NOT_ALLOWED);
    }

    @Test
    public void shouldAcceptNotification() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"),
                commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.ACCEPTED);
    }

    @Test
    public void shouldReturnMethodNotFound() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/list\"}"), commonHandler);

        assertThat(json(response).at("/error/code").asInt()).isEqualTo(-32601);
    }

    @Test
    public void shouldReturnParseError() throws Exception {
        CommonResponse response =
                embedded().handle(post(basic("alice", "secret"), "{not json"), commonHandler);

        assertThat(response.getStatus()).isEqualTo(HttpResponseStatus.BAD_REQUEST);
        assertThat(json(response).at("/error/code").asInt()).isEqualTo(-32700);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shouldDispatchTransactionSummariesWithDefaults() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/transaction/summaries"), anyMap(),
                eq(user))).thenReturn(ok("{\"overall\":{},\"transactions\":[]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_summaries", "{\"transactionType\":\"Web\"}")),
                commonHandler);

        ArgumentCaptor<Map<String, List<String>>> captor = ArgumentCaptor.forClass(Map.class);
        verify(commonHandler).handleInternalGet(eq("/backend/transaction/summaries"),
                captor.capture(), eq(user));
        Map<String, List<String>> params = captor.getValue();
        assertThat(params.get("agent-rollup-id")).containsExactly("");
        assertThat(params.get("transaction-type")).containsExactly("Web");
        assertThat(params.get("sort-order")).containsExactly("total-time");
        assertThat(params.get("limit")).containsExactly("20");
        // default "to" is rounded up to the minute, like the UI
        assertThat(params.get("to")).containsExactly(Long.toString(NOW_ROUNDED_UP));
        assertThat(params.get("from")).containsExactly(Long.toString(NOW_ROUNDED_UP - 3600000));

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isFalse();
        JsonNode text = mapper.readTree(result.at("/content/0/text").asText());
        assertThat(text.has("overall")).isTrue();
        assertThat(text.path("glowrootUrl").asText()).isEqualTo(
                "http://localhost:4000/o/glowroot/transaction/average?transaction-type=Web"
                        + "&from=" + (NOW_ROUNDED_UP - 3600000) + "&to=" + NOW_ROUNDED_UP);
    }

    @Test
    public void shouldReportMissingRequiredArgumentAsToolError() throws Exception {
        CommonResponse response = embedded().handle(
                post(basic("alice", "secret"), toolCall("get_transaction_summaries", "{}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("transactionType");
    }

    @Test
    public void shouldRequireAgentIdInCentral() throws Exception {
        CommonResponse response = central().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_summaries", "{\"transactionType\":\"Web\"}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("agentId");
        verify(commonHandler, never()).handleInternalGet(anyString(), anyMap(),
                any(Authentication.class));
    }

    @Test
    public void shouldReportPermissionDeniedAsToolError() throws Exception {
        when(commonHandler.handleInternalGet(anyString(), anyMap(), eq(user)))
                .thenReturn(new CommonResponse(HttpResponseStatus.FORBIDDEN));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_overview", "{\"transactionType\":\"Web\"}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("not permitted");
    }

    @Test
    public void shouldStripChartSeriesByDefault() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/transaction/average"), anyMap(),
                eq(user))).thenReturn(
                        ok("{\"dataSeries\":[1,2,3],\"mergedAggregate\":{\"x\":1}}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_overview", "{\"transactionType\":\"Web\"}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.has("dataSeries")).isFalse();
        assertThat(text.at("/mergedAggregate/x").asInt()).isEqualTo(1);
    }

    @Test
    public void shouldConvertTracePoints() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/error/points"), anyMap(), eq(user)))
                .thenReturn(ok("{\"normalPoints\":[],\"errorPoints\":[[123,45.6,\"\",\"abc\"]],"
                        + "\"partialPoints\":[],\"limitExceeded\":true}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("list_traces", "{\"transactionType\":\"Web\",\"errorsOnly\":true}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.at("/traces/0/traceId").asText()).isEqualTo("abc");
        assertThat(text.at("/traces/0/captureTime").asLong()).isEqualTo(123);
        assertThat(text.at("/traces/0/durationMillis").asDouble()).isEqualTo(45.6);
        assertThat(text.at("/traces/0/error").asBoolean()).isTrue();
        assertThat(text.path("limitExceeded").asBoolean()).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void shouldDispatchGaugeValues() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/jvm/gauges"), anyMap(), eq(user)))
                .thenReturn(ok("{\"dataSeries\":[],\"dataPointIntervalMillis\":5000,"
                        + "\"allGauges\":[{\"name\":\"g\"}]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_gauge_values", "{\"gaugeNames\":[\"a\",\"b\"],\"from\":1,\"to\":2}")),
                commonHandler);

        ArgumentCaptor<Map<String, List<String>>> captor = ArgumentCaptor.forClass(Map.class);
        verify(commonHandler).handleInternalGet(eq("/backend/jvm/gauges"), captor.capture(),
                eq(user));
        assertThat(captor.getValue().get("gauge-name")).containsExactly("a", "b");
        assertThat(captor.getValue().get("from")).containsExactly("1");
        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.has("allGauges")).isFalse();
        assertThat(text.path("dataPointIntervalMillis").asInt()).isEqualTo(5000);
    }

    @Test
    public void shouldInlineSharedQueryTextsInTraceQueriesSortedByTotalTime() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/trace/queries"), anyMap(), eq(user)))
                .thenReturn(ok("{\"queries\":["
                        + "{\"type\":\"SQL\",\"sharedQueryTextIndex\":0,"
                        + "\"totalDurationNanos\":10.0,\"executionCount\":1},"
                        + "{\"type\":\"SQL\",\"sharedQueryTextIndex\":1,"
                        + "\"totalDurationNanos\":99.0,\"executionCount\":312}],"
                        + "\"sharedQueryTexts\":[{\"fullText\":\"select 1\"},"
                        + "{\"truncatedText\":\"select a\",\"truncatedEndText\":\"where b=?\","
                        + "\"fullTextSha1\":\"abc\"}]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_trace_queries", "{\"traceId\":\"t1\"}")), commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.has("sharedQueryTexts")).isFalse();
        JsonNode first = text.at("/queries/0");
        assertThat(first.path("executionCount").asInt()).isEqualTo(312);
        assertThat(first.path("queryText").asText()).isEqualTo("select a ... where b=?");
        assertThat(first.path("fullQueryTextSha1").asText()).isEqualTo("abc");
        assertThat(first.has("sharedQueryTextIndex")).isFalse();
        assertThat(text.at("/queries/1/queryText").asText()).isEqualTo("select 1");
        assertThat(text.at("/queries/1").has("fullQueryTextSha1")).isFalse();
    }

    @Test
    public void shouldInlineAbbreviatedQueryTextsInTraceEntries() throws Exception {
        String longQuery = "select " + Strings.repeat("x", 400);
        when(commonHandler.handleInternalGet(eq("/backend/trace/entries"), anyMap(), eq(user)))
                .thenReturn(ok("{\"entries\":[{\"message\":\"m\",\"childEntries\":["
                        + "{\"queryMessage\":{\"sharedQueryTextIndex\":0,\"prefix\":\"jdbc: \"}}"
                        + "]}],\"sharedQueryTexts\":[{\"fullText\":\"" + longQuery + "\"}]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_trace_entries", "{\"traceId\":\"t1\"}")), commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.has("sharedQueryTexts")).isFalse();
        assertThat(text.path("totalEntries").asInt()).isEqualTo(2);
        assertThat(text.at("/entries/1/depth").asInt()).isEqualTo(1);
        JsonNode queryMessage = text.at("/entries/1/queryMessage");
        assertThat(queryMessage.has("sharedQueryTextIndex")).isFalse();
        assertThat(queryMessage.path("prefix").asText()).isEqualTo("jdbc: ");
        String queryText = queryMessage.path("queryText").asText();
        assertThat(queryText).startsWith("select xxx").contains(" ... ");
        assertThat(queryText.length()).isEqualTo(120 + 5 + 120);
    }

    @Test
    public void shouldAnnotateWriteAndDeleteTools() throws Exception {
        CommonResponse response = embedded().handle(
                post(basic("alice", "secret"),
                        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"),
                commonHandler);

        JsonNode tools = json(response).at("/result/tools");
        assertThat(annotations(tools, "get_trace").path("readOnlyHint").asBoolean()).isTrue();
        JsonNode createGauge = annotations(tools, "create_gauge");
        assertThat(createGauge.path("readOnlyHint").asBoolean()).isFalse();
        assertThat(createGauge.path("destructiveHint").asBoolean()).isFalse();
        JsonNode deleteGauge = annotations(tools, "delete_gauge");
        assertThat(deleteGauge.path("readOnlyHint").asBoolean()).isFalse();
        assertThat(deleteGauge.path("destructiveHint").asBoolean()).isTrue();
        assertThat(annotations(tools, "apply_instrumentation_changes").path("readOnlyHint")
                .asBoolean()).isFalse();
    }

    @Test
    public void shouldSetDefaultSlowTraceThresholdKeepingVersionAndOverrides() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/transaction"), anyMap(),
                eq(user))).thenReturn(ok(TRANSACTION_CONFIG));
        when(commonHandler.handleInternalPost(eq("/backend/config/transaction"), anyMap(),
                anyString(), eq(user))).thenReturn(ok(TRANSACTION_CONFIG));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("set_slow_trace_threshold", "{\"thresholdMillis\":500}")),
                commonHandler);

        JsonNode body = capturePostBody("/backend/config/transaction");
        assertThat(body.path("slowThresholdMillis").asInt()).isEqualTo(500);
        assertThat(body.path("version").asText()).isEqualTo("v1");
        assertThat(body.path("slowThresholdOverrides").size()).isEqualTo(1);
        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("change").asText()).contains("2000 ms -> 500 ms");
        assertThat(text.path("glowrootUrl").asText())
                .isEqualTo("http://localhost:4000/o/glowroot/config/transaction");
    }

    @Test
    public void shouldUpdateAndAddSlowTraceThresholdOverrides() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/transaction"), anyMap(),
                eq(user))).thenReturn(ok(TRANSACTION_CONFIG));
        when(commonHandler.handleInternalPost(eq("/backend/config/transaction"), anyMap(),
                anyString(), eq(user))).thenReturn(ok(TRANSACTION_CONFIG));

        embedded().handle(post(basic("alice", "secret"),
                toolCall("set_slow_trace_threshold", "{\"thresholdMillis\":100,"
                        + "\"transactionType\":\"Web\",\"transactionName\":\"/home\"}")),
                commonHandler);

        JsonNode overrides = capturePostBody("/backend/config/transaction")
                .path("slowThresholdOverrides");
        assertThat(overrides.size()).isEqualTo(1);
        assertThat(overrides.at("/0/thresholdMillis").asInt()).isEqualTo(100);
    }

    @Test
    public void shouldCreateGauge() throws Exception {
        when(commonHandler.handleInternalPost(eq("/backend/config/gauges/add"), anyMap(),
                anyString(), eq(user))).thenReturn(ok("{\"config\":{\"version\":\"g1\"}}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_gauge", "{\"mbeanObjectName\":\"app:type=Pool\","
                        + "\"attributes\":[\"Active\",\"Served\"],"
                        + "\"counterAttributes\":[\"Served\"]}")),
                commonHandler);

        JsonNode body = capturePostBody("/backend/config/gauges/add");
        assertThat(body.path("mbeanObjectName").asText()).isEqualTo("app:type=Pool");
        assertThat(body.at("/mbeanAttributes/0/counter").asBoolean()).isFalse();
        assertThat(body.at("/mbeanAttributes/1/name").asText()).isEqualTo("Served");
        assertThat(body.at("/mbeanAttributes/1/counter").asBoolean()).isTrue();
        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.at("/gaugeNames/1").asText()).isEqualTo("app:type=Pool:Served[counter]");
        assertThat(text.path("glowrootUrl").asText())
                .isEqualTo("http://localhost:4000/o/glowroot/config/gauge?v=g1");
        assertThat(text.path("gaugeValuesUrl").asText()).startsWith(
                "http://localhost:4000/o/glowroot/jvm/gauges?gauge-name=app%3Atype%3DPool%3AActive"
                        + "&gauge-name=app%3Atype%3DPool%3AServed%5Bcounter%5D&from=");
    }

    @Test
    public void shouldCreateTransactionInstrumentationWithDefaults() throws Exception {
        when(commonHandler.handleInternalPost(eq("/backend/config/instrumentation/add"),
                anyMap(), anyString(), eq(user)))
                        .thenReturn(ok("{\"config\":{\"version\":\"i1\"}}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Job\","
                        + "\"methodName\":\"run\",\"captureKind\":\"transaction\","
                        + "\"transactionType\":\"Background\"}")),
                commonHandler);

        JsonNode body = capturePostBody("/backend/config/instrumentation/add");
        assertThat(body.path("captureKind").asText()).isEqualTo("transaction");
        assertThat(body.at("/methodParameterTypes/0").asText()).isEqualTo("..");
        assertThat(body.path("timerName").asText()).isEqualTo("Job run");
        assertThat(body.path("traceEntryMessageTemplate").asText())
                .isEqualTo("Job.{{methodName}}()");
        assertThat(body.path("transactionType").asText()).isEqualTo("Background");
        assertThat(body.path("transactionNameTemplate").asText())
                .isEqualTo("Job.{{methodName}}");
        assertThat(body.path("alreadyInTransactionBehavior").asText())
                .isEqualTo("capture-trace-entry");
        assertThat(body.path("transactionSlowThresholdMillis").isNull()).isTrue();
        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("glowrootUrl").asText())
                .isEqualTo("http://localhost:4000/o/glowroot/config/instrumentation?v=i1");
        assertThat(text.path("nextStep").asText()).contains("apply_instrumentation_changes");
    }

    @Test
    public void shouldCreateTimerInstrumentationWithoutTraceEntryOrTransactionFields()
            throws Exception {
        when(commonHandler.handleInternalPost(eq("/backend/config/instrumentation/add"),
                anyMap(), anyString(), eq(user)))
                        .thenReturn(ok("{\"config\":{\"version\":\"i2\"}}"));

        embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Dao\","
                        + "\"methodName\":\"find*\",\"captureKind\":\"timer\","
                        + "\"timerName\":\"dao\",\"transactionType\":\"ignored\"}")),
                commonHandler);

        JsonNode body = capturePostBody("/backend/config/instrumentation/add");
        assertThat(body.path("timerName").asText()).isEqualTo("dao");
        assertThat(body.path("traceEntryMessageTemplate").asText()).isEmpty();
        assertThat(body.path("transactionType").asText()).isEmpty();
        assertThat(body.path("alreadyInTransactionBehavior").isNull()).isTrue();
    }

    @Test
    public void shouldDeriveValidTimerNameFromWildcardMethod() throws Exception {
        when(commonHandler.handleInternalPost(eq("/backend/config/instrumentation/add"),
                anyMap(), anyString(), eq(user)))
                        .thenReturn(ok("{\"config\":{\"version\":\"i3\"}}"));

        embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Outer$Dao\","
                        + "\"methodName\":\"find*\",\"captureKind\":\"timer\"}")),
                commonHandler);

        assertThat(capturePostBody("/backend/config/instrumentation/add").path("timerName")
                .asText()).isEqualTo("Dao find");
    }

    @Test
    public void shouldRejectInvalidTimerName() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Dao\","
                        + "\"methodName\":\"find\",\"captureKind\":\"timer\","
                        + "\"timerName\":\"dao.find\"}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("letters, digits and spaces");
        verify(commonHandler, never()).handleInternalPost(anyString(), anyMap(), anyString(),
                any(Authentication.class));
    }

    @Test
    public void shouldRequireTransactionTypeForTransactionInstrumentation() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Job\","
                        + "\"methodName\":\"run\",\"captureKind\":\"transaction\"}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("transactionType");
        verify(commonHandler, never()).handleInternalPost(anyString(), anyMap(), anyString(),
                any(Authentication.class));
    }

    @Test
    public void shouldApplyInstrumentationChanges() throws Exception {
        when(commonHandler.handleInternalPost(eq("/backend/config/reweave"), anyMap(),
                anyString(), eq(user))).thenReturn(ok("{\"classes\":3}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("apply_instrumentation_changes", "{}")), commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("classes").asInt()).isEqualTo(3);
        assertThat(text.path("glowrootUrl").asText())
                .isEqualTo("http://localhost:4000/o/glowroot/config/instrumentation-list");
    }

    @Test
    public void shouldLinkEachTraceToTheUi() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/transaction/points"), anyMap(),
                eq(user))).thenReturn(ok("{\"normalPoints\":[[123,45.6,\"\",\"abc\"]],"
                        + "\"errorPoints\":[],\"partialPoints\":[]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("list_traces", "{\"transactionType\":\"Web\",\"from\":1,\"to\":2}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.at("/traces/0/glowrootUrl").asText()).isEqualTo(
                "http://localhost:4000/o/glowroot/transaction/traces?transaction-type=Web"
                        + "&from=1&to=2&modal-trace-id=abc");
    }

    @Test
    public void shouldLinkTraceWithAgentInCentralBehindReverseProxy() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/trace/header"), anyMap(), eq(user)))
                .thenReturn(ok("{\"transactionType\":\"Web\",\"transactionName\":\"/home\","
                        + "\"startTime\":3600000,\"captureTime\":3601000}"));
        CommonRequest request = post(basic("alice", "secret"),
                toolCall("get_trace", "{\"agentId\":\"node 1\",\"traceId\":\"abc\"}"));
        when(request.getHeader("X-Forwarded-Proto")).thenReturn("https");
        when(request.getHeader("X-Forwarded-Host")).thenReturn("apm.example.com, proxy");

        CommonResponse response = central().handle(request, commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("glowrootUrl").asText()).isEqualTo(
                "https://apm.example.com/o/glowroot/transaction/traces?agent-id=node%201"
                        + "&transaction-type=Web&transaction-name=%2Fhome&from=1800000"
                        + "&to=5401000&modal-agent-id=node%201&modal-trace-id=abc");
    }

    @Test
    public void shouldReportUnknownTraceAsToolError() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/trace/header"), anyMap(), eq(user)))
                .thenReturn(ok("{\"expired\":true}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_trace", "{\"traceId\":\"nope\"}")), commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("Trace not found");
    }

    @Test
    public void shouldReturnStructuredContentWithIntegerDurations() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/transaction/summaries"), anyMap(),
                eq(user))).thenReturn(ok("{\"overall\":{\"totalDurationNanos\":2.85202499E10}}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_summaries", "{\"transactionType\":\"Web\"}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.at("/structuredContent/overall/totalDurationNanos").isIntegralNumber())
                .isTrue();
        assertThat(result.at("/content/0/text").asText())
                .contains("\"totalDurationNanos\":28520249900");
    }

    @Test
    public void shouldSortAndLimitTransactionQueries() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/transaction/queries"), anyMap(),
                eq(user))).thenReturn(ok("[{\"truncatedQueryText\":\"a\","
                        + "\"totalDurationNanos\":10,\"executionCount\":1},"
                        + "{\"truncatedQueryText\":\"b\",\"totalDurationNanos\":5,"
                        + "\"executionCount\":312},{\"truncatedQueryText\":\"c\","
                        + "\"totalDurationNanos\":1,\"executionCount\":2}]"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_queries", "{\"transactionType\":\"Web\","
                        + "\"sortBy\":\"execution-count\",\"limit\":2}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("queryCount").asInt()).isEqualTo(3);
        assertThat(text.path("queries").size()).isEqualTo(2);
        assertThat(text.at("/queries/0/truncatedQueryText").asText()).isEqualTo("b");
    }

    @Test
    public void shouldAddMissingAttributesToExistingGauge() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/gauges"), anyMap(), eq(user)))
                .thenReturn(ok("[{\"config\":{\"mbeanObjectName\":\"app:type=Pool\","
                        + "\"mbeanAttributes\":[{\"name\":\"Active\",\"counter\":false}],"
                        + "\"version\":\"g1\"}}]"));
        when(commonHandler.handleInternalPost(eq("/backend/config/gauges/update"), anyMap(),
                anyString(), eq(user))).thenReturn(ok("{\"config\":{\"version\":\"g2\"}}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_gauge", "{\"mbeanObjectName\":\"app:type=Pool\","
                        + "\"attributes\":[\"Active\",\"Idle\"]}")),
                commonHandler);

        JsonNode body = capturePostBody("/backend/config/gauges/update");
        assertThat(body.path("version").asText()).isEqualTo("g1");
        assertThat(body.path("mbeanAttributes").size()).isEqualTo(2);
        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("updated").asBoolean()).isTrue();
        assertThat(text.at("/addedAttributes/0").asText()).isEqualTo("Idle");
    }

    @Test
    public void shouldNotDuplicateExistingGauge() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/gauges"), anyMap(), eq(user)))
                .thenReturn(ok("[{\"config\":{\"mbeanObjectName\":\"app:type=Pool\","
                        + "\"mbeanAttributes\":[{\"name\":\"Active\",\"counter\":false}],"
                        + "\"version\":\"g1\"}}]"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_gauge", "{\"mbeanObjectName\":\"app:type=Pool\","
                        + "\"attributes\":[\"Active\"]}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("unchanged").asBoolean()).isTrue();
        verify(commonHandler, never()).handleInternalPost(anyString(), anyMap(), anyString(),
                any(Authentication.class));
    }

    @Test
    public void shouldRejectUnknownGaugeAttribute() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/mbean-attributes"), anyMap(),
                eq(user))).thenReturn(ok("{\"mbeanAttributes\":[\"Active\",\"Idle\"]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_gauge", "{\"mbeanObjectName\":\"app:type=Pool\","
                        + "\"attributes\":[\"Busy\"]}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("Unknown attributes [Busy]")
                .contains("Idle");
    }

    @Test
    public void shouldDryRunInstrumentationWithWarnings() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/matching-class-names"),
                anyMap(), eq(user))).thenReturn(ok("[\"com.acme.Dao\"]"));
        when(commonHandler.handleInternalGet(eq("/backend/config/method-signatures"), anyMap(),
                eq(user))).thenReturn(ok("[{\"name\":\"find\",\"parameterTypes\":[\"long\"],"
                        + "\"returnType\":\"void\",\"modifiers\":[]}]"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Dao\","
                        + "\"methodName\":\"find\",\"captureKind\":\"timer\","
                        + "\"methodParameterTypes\":[\"java.lang.String\"],\"dryRun\":true}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("dryRun").asBoolean()).isTrue();
        assertThat(text.at("/config/timerName").asText()).isEqualTo("Dao find");
        assertThat(text.at("/methodSignatures/0/parameterTypes/0").asText()).isEqualTo("long");
        assertThat(text.at("/warnings/0").asText()).contains("no overload");
        verify(commonHandler, never()).handleInternalPost(anyString(), anyMap(), anyString(),
                any(Authentication.class));
    }

    @Test
    public void shouldFlagTruncatedTraceEntries() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/trace/header"), anyMap(), eq(user)))
                .thenReturn(ok("{\"transactionType\":\"Web\",\"transactionName\":\"/\","
                        + "\"captureTime\":1,\"entryLimitExceeded\":true}"));
        when(commonHandler.handleInternalGet(eq("/backend/trace/entries"), anyMap(), eq(user)))
                .thenReturn(ok("{\"entries\":[{\"durationNanos\":1,\"message\":\"m\"}],"
                        + "\"sharedQueryTexts\":[]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_trace_entries", "{\"traceId\":\"t1\",\"aggregate\":true}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("entryLimitExceeded").asBoolean()).isTrue();
        assertThat(text.at("/warnings/0").asText()).contains("partial")
                .contains("get_trace_queries");
    }

    @Test
    public void shouldReportStaleVersion() throws Exception {
        when(commonHandler.handleInternalPost(eq("/backend/config/gauges/remove"), anyMap(),
                anyString(), eq(user))).thenReturn(new CommonResponse(
                        HttpResponseStatus.INTERNAL_SERVER_ERROR, MediaType.JSON_UTF_8,
                        "{\"message\":\"org.glowroot.common2.repo.ConfigRepository$"
                                + "OptimisticLockException\"}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("delete_gauge", "{\"version\":\"old\"}")), commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("version is stale");
    }

    @Test
    public void shouldRejectOutOfRangeTemplateArgument() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/config/matching-class-names"),
                anyMap(), eq(user))).thenReturn(ok("[\"com.acme.Dao\"]"));
        when(commonHandler.handleInternalGet(eq("/backend/config/method-signatures"), anyMap(),
                eq(user))).thenReturn(ok("[{\"name\":\"find\",\"parameterTypes\":[\"long\"],"
                        + "\"returnType\":\"void\",\"modifiers\":[]}]"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Dao\","
                        + "\"methodName\":\"find\",\"captureKind\":\"trace-entry\","
                        + "\"traceEntryMessageTemplate\":\"find {{9}}\",\"dryRun\":true}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("{{9}}")
                .contains("takes 1 argument");
    }

    @Test
    public void shouldRejectUnknownTemplatePlaceholderAndWarnOnWildcard() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.Dao\","
                        + "\"methodName\":\"find\",\"captureKind\":\"trace-entry\","
                        + "\"traceEntryMessageTemplate\":\"find {{arg0}}\",\"dryRun\":true}")),
                commonHandler);
        assertThat(json(response).at("/result/content/0/text").asText())
                .contains("unknown placeholder {{arg0}}");

        response = embedded().handle(post(basic("alice", "secret"),
                toolCall("create_instrumentation", "{\"className\":\"com.acme.ModelListener\","
                        + "\"methodName\":\"*\",\"captureKind\":\"timer\",\"dryRun\":true}")),
                commonHandler);
        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.path("warnings").toString()).contains("wildcard");
    }

    @Test
    public void shouldReportUnknownMBean() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/jvm/mbean-attribute-map"), anyMap(),
                eq(user))).thenReturn(new CommonResponse(HttpResponseStatus.NOT_FOUND));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("read_mbean_values", "{\"objectName\":\"nope:type=X\"}")),
                commonHandler);

        assertThat(json(response).at("/result/content/0/text").asText())
                .isEqualTo("MBean not found: nope:type=X (use search_mbeans)");
    }

    @Test
    public void shouldKeepTransactionCountsWithinTheMergedRange() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/transaction/average"), anyMap(),
                eq(user))).thenReturn(ok("{\"transactionCounts\":{\"1000\":3,\"1500\":2,"
                        + "\"2000\":1,\"2500\":9},\"mergedAggregate\":{\"transactionCount\":3}}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_transaction_overview",
                        "{\"transactionType\":\"Web\",\"from\":1000,\"to\":2000}")),
                commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        // same rule as mergedAggregate: from excluded, to included
        assertThat(text.path("transactionCounts").toString()).isEqualTo("{\"1500\":2,\"2000\":1}");
    }

    @Test
    public void shouldWarnOnUnknownGaugeName() throws Exception {
        when(commonHandler.handleInternalGet(eq("/backend/jvm/gauges"), anyMap(), eq(user)))
                .thenReturn(ok("{\"dataSeries\":[{\"name\":\"nope\",\"data\":[]}],"
                        + "\"allGauges\":[{\"name\":\"java.lang:type=Memory:HeapMemoryUsage.used\"}]}"));

        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                toolCall("get_gauge_values", "{\"gaugeNames\":[\"nope\"]}")), commonHandler);

        JsonNode text = mapper.readTree(json(response).at("/result/content/0/text").asText());
        assertThat(text.at("/warnings/0").asText()).contains("nope").contains("list_gauges");
    }

    @Test
    public void shouldRejectTraceLookupWithAgentRollupId() throws Exception {
        CommonResponse response = central().handle(post(basic("alice", "secret"),
                toolCall("get_trace", "{\"agentId\":\"group::\",\"traceId\":\"abc\"}")),
                commonHandler);

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isTrue();
        assertThat(result.at("/content/0/text").asText()).contains("rollup");
    }

    @Test
    public void shouldHandleBatch() throws Exception {
        CommonResponse response = embedded().handle(post(basic("alice", "secret"),
                "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"},"
                        + "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"},"
                        + "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}]"),
                commonHandler);

        JsonNode node = json(response);
        assertThat(node.isArray()).isTrue();
        assertThat(node.size()).isEqualTo(2);
    }

    private static final String TRANSACTION_CONFIG = "{\"config\":{\"slowThresholdMillis\":2000,"
            + "\"profilingIntervalMillis\":1000,\"captureThreadStats\":true,"
            + "\"slowThresholdOverrides\":[{\"transactionType\":\"Web\","
            + "\"transactionName\":\"/home\",\"user\":\"\",\"thresholdMillis\":5000}],"
            + "\"version\":\"v1\"}}";

    private JsonNode capturePostBody(String path) throws Exception {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(commonHandler).handleInternalPost(eq(path), anyMap(), captor.capture(),
                eq(user));
        return mapper.readTree(captor.getValue());
    }

    private static JsonNode annotations(JsonNode tools, String name) {
        for (JsonNode tool : tools) {
            if (tool.path("name").asText().equals(name)) {
                return tool.path("annotations");
            }
        }
        throw new AssertionError("tool not found: " + name);
    }

    private McpServer embedded() {
        return new McpServer(false, false, "0.0.1-test", httpSessionManager,
                Suppliers.ofInstance(false), clock());
    }

    private McpServer central() {
        return new McpServer(true, false, "0.0.1-test", httpSessionManager,
                Suppliers.ofInstance(false), clock());
    }

    private static Clock clock() {
        Clock clock = mock(Clock.class);
        when(clock.currentTimeMillis()).thenReturn(NOW);
        return clock;
    }

    private static Authentication authentication(String username, boolean anonymous,
            ImmutableSet<String> roles) {
        return ImmutableAuthentication.builder()
                .central(false)
                .offlineViewer(false)
                .anonymous(anonymous)
                .ldap(false)
                .caseAmbiguousUsername(username)
                .roles(roles)
                .configRepository(mock(ConfigRepository.class))
                .build();
    }

    private static String basic(String username, String password) {
        return "Basic " + BaseEncoding.base64().encode((username + ":" + password).getBytes(UTF_8));
    }

    private static String toolCall(String name, String arguments) {
        return "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\""
                + name + "\",\"arguments\":" + arguments + "}}";
    }

    private static CommonRequest post(String authorization, String content) throws Exception {
        CommonRequest request = mock(CommonRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getPath()).thenReturn("/mcp");
        when(request.getContextPath()).thenReturn("/o/glowroot/");
        when(request.getHeader(HttpHeaderNames.HOST.toString())).thenReturn("localhost:4000");
        when(request.getHeader(HttpHeaderNames.AUTHORIZATION)).thenReturn(authorization);
        when(request.getContent()).thenReturn(content);
        return request;
    }

    private static CommonResponse ok(String json) {
        return new CommonResponse(HttpResponseStatus.OK, MediaType.JSON_UTF_8, json);
    }

    private static JsonNode json(CommonResponse response) throws Exception {
        return mapper.readTree((String) response.getContent());
    }
}
