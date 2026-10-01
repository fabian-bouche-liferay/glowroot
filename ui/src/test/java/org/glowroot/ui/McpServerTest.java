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
    public void shouldListReadOnlyTools() throws Exception {
        CommonResponse response = embedded().handle(
                post(basic("alice", "secret"),
                        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"),
                commonHandler);

        JsonNode tools = json(response).at("/result/tools");
        List<String> names = ImmutableList.copyOf(tools.findValuesAsText("name"));
        assertThat(names).contains("list_agents", "list_transaction_types",
                "get_transaction_summaries", "get_transaction_overview", "list_traces",
                "get_trace", "list_gauges", "get_gauge_values");
        for (JsonNode tool : tools) {
            assertThat(tool.at("/annotations/readOnlyHint").asBoolean()).isTrue();
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
        assertThat(params.get("to")).containsExactly(Long.toString(NOW));
        assertThat(params.get("from")).containsExactly(Long.toString(NOW - 3600000));

        JsonNode result = json(response).path("result");
        assertThat(result.path("isError").asBoolean()).isFalse();
        assertThat(result.at("/content/0/text").asText())
                .isEqualTo("{\"overall\":{},\"transactions\":[]}");
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
        JsonNode queryMessage = text.at("/entries/0/childEntries/0/queryMessage");
        assertThat(queryMessage.has("sharedQueryTextIndex")).isFalse();
        assertThat(queryMessage.path("prefix").asText()).isEqualTo("jdbc: ");
        String queryText = queryMessage.path("queryText").asText();
        assertThat(queryText).startsWith("select xxx").contains(" ... ");
        assertThat(queryText.length()).isEqualTo(120 + 5 + 120);
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

    private McpServer embedded() {
        return new McpServer(false, false, "0.0.1-test", httpSessionManager, clock());
    }

    private McpServer central() {
        return new McpServer(true, false, "0.0.1-test", httpSessionManager, clock());
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
