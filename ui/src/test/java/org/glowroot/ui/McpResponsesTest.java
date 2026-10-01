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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class McpResponsesTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    // 100 samples: servlet trunk -> app.Service.handle, which branches into a slow query (70,
    // waiting on the socket) and template rendering (30, runnable)
    private static final String PROFILE = "{\"unfilteredSampleCount\":100,\"rootNodes\":[{"
            + "\"stackTraceElement\":\"java.lang.Thread.run(Thread.java:1583)\",\"sampleCount\":100,"
            + "\"childNodes\":[{\"stackTraceElement\":\"org.apache.catalina.core.StandardWrapper"
            + "Valve.invoke(StandardWrapperValve.java:1)\",\"sampleCount\":100,\"childNodes\":[{"
            + "\"stackTraceElement\":\"app.Service.handle(Service.java:10)\",\"sampleCount\":100,"
            + "\"childNodes\":[{\"stackTraceElement\":\"app.Dao.query(Dao.java:5)\","
            + "\"sampleCount\":70,\"childNodes\":[{\"stackTraceElement\":"
            + "\"java.net.SocketInputStream.read(SocketInputStream.java:1)\",\"sampleCount\":70,"
            + "\"leafThreadState\":\"RUNNABLE\"}]},{\"stackTraceElement\":"
            + "\"app.View.render(View.java:3)\",\"sampleCount\":30,\"leafThreadState\":"
            + "\"RUNNABLE\"}]}]}]}]}";

    @Test
    public void shouldSummarizeProfile() throws Exception {
        ObjectNode summary = McpResponses.summarizeProfile(mapper.readTree(PROFILE), 3, 5,
                ImmutableList.of("java.lang.Thread.", "org.apache.catalina."));

        assertThat(summary.path("sampleCount").asLong()).isEqualTo(100);
        assertThat(summary.at("/topFramesSelf/0/frame").asText())
                .startsWith("java.net.SocketInputStream.read");
        assertThat(summary.at("/topFramesSelf/0/percent").asDouble()).isEqualTo(70.0);
        assertThat(summary.at("/topFramesSelf/1/frame").asText()).startsWith("app.View.render");
        assertThat(summary.at("/leafThreadStates/RUNNABLE").asLong()).isEqualTo(100);
        JsonNode hotPath = summary.path("hotPath");
        // the collapsed trunk is not reported, the first reported frame says how much was hidden
        assertThat(hotPath.at("/0/frame").asText()).startsWith("app.Service.handle");
        assertThat(hotPath.at("/0/collapsedFramesAbove").asInt()).isEqualTo(2);
        assertThat(hotPath.at("/0/branches/0/frame").asText()).startsWith("app.Dao.query");
        assertThat(hotPath.at("/0/branches/1/percent").asDouble()).isEqualTo(30.0);
        assertThat(hotPath.at("/2/frame").asText()).startsWith("java.net.SocketInputStream");
        assertThat(hotPath.at("/2/leafThreadState").asText()).isEqualTo("RUNNABLE");
    }

    @Test
    public void shouldSummarizeEmptyProfile() throws Exception {
        ObjectNode summary = McpResponses.summarizeProfile(
                mapper.readTree("{\"unfilteredSampleCount\":0,\"rootNodes\":[]}"), 3, 5,
                ImmutableList.<String>of());

        assertThat(summary.path("sampleCount").asLong()).isZero();
        assertThat(summary.has("hotPath")).isFalse();
    }

    @Test
    public void shouldNormalizeNumbers() throws Exception {
        JsonNode node = mapper.readTree("{\"totalDurationNanos\":2.85202499E10,"
                + "\"totalCpuNanos\":1.5625E8,\"durationMillis\":45.6,\"transactionCount\":2.0,"
                + "\"data\":[[1790854380000,2.12441864E8],[1,0.5]]}");

        McpResponses.normalizeNumbers(node);

        assertThat(node.toString()).isEqualTo("{\"totalDurationNanos\":28520249900,"
                + "\"totalCpuNanos\":156250000,\"durationMillis\":45.6,\"transactionCount\":2,"
                + "\"data\":[[1790854380000,212441864],[1,0.5]]}");
    }

    @Test
    public void shouldExposePercentilesInMillisAndNanos() throws Exception {
        JsonNode node = mapper.readTree("{\"mergedAggregate\":{\"percentileValues\":["
                + "{\"dataSeriesName\":\"50th percentile\",\"value\":13692000}]}}");

        McpResponses.addPercentileMillis(node);

        JsonNode value = node.at("/mergedAggregate/percentileValues/0");
        assertThat(value.has("value")).isFalse();
        assertThat(value.path("valueNanos").asLong()).isEqualTo(13692000);
        assertThat(value.path("valueMillis").asDouble()).isEqualTo(13.692);
    }

    @Test
    public void shouldPageAndFilterEntries() throws Exception {
        JsonNode entries = mapper.readTree(ENTRIES);

        ObjectNode page = McpResponses.pageEntries(entries, 0, "query", "", false, 1, 1);

        assertThat(page.path("totalEntries").asInt()).isEqualTo(4);
        assertThat(page.path("matchingEntries").asInt()).isEqualTo(3);
        assertThat(page.path("offset").asInt()).isEqualTo(1);
        assertThat(page.path("entries").size()).isEqualTo(1);
        assertThat(page.at("/entries/0/depth").asInt()).isEqualTo(1);
        assertThat(page.at("/entries/0/durationNanos").asLong()).isEqualTo(3000000);
        assertThat(page.path("hasMore").asBoolean()).isTrue();
    }

    @Test
    public void shouldFilterEntriesByDuration() throws Exception {
        ObjectNode page = McpResponses.pageEntries(mapper.readTree(ENTRIES), 1.5, "all", "",
                false, 0, 100);

        assertThat(page.path("matchingEntries").asInt()).isEqualTo(2);
    }

    @Test
    public void shouldAggregateEntriesByQueryText() throws Exception {
        ObjectNode page = McpResponses.pageEntries(mapper.readTree(ENTRIES), 0, "all", "",
                true, 0, 100);

        JsonNode first = page.at("/groups/0");
        assertThat(first.path("queryText").asText()).isEqualTo("select a");
        assertThat(first.path("count").asInt()).isEqualTo(2);
        assertThat(first.path("totalDurationNanos").asLong()).isEqualTo(4000000);
        assertThat(first.path("maxDurationNanos").asLong()).isEqualTo(3000000);
        assertThat(page.at("/groups/1/message").asText()).isEqualTo("render");
    }

    @Test
    public void shouldCompactThreadDump() throws Exception {
        JsonNode threadDump = mapper.readTree("{\"transactions\":[{\"traceId\":\"t1\","
                + "\"threads\":[{\"name\":\"http-1\",\"state\":\"RUNNABLE\","
                + "\"stackTraceElements\":[\"a\",\"b\",\"c\"]}]}],"
                + "\"unmatchedThreadsByStackTrace\":["
                + "[{\"name\":\"pool-1\",\"state\":\"WAITING\",\"stackTraceElements\":[\"x\"]},"
                + "{\"name\":\"pool-2\",\"state\":\"WAITING\",\"stackTraceElements\":[\"x\"]}]]}");

        ObjectNode compact = McpResponses.compactThreadDump(threadDump, 2, false);

        assertThat(compact.at("/transactions/0/threads/0/stackTraceElements").size())
                .isEqualTo(2);
        assertThat(compact.at("/transactions/0/threads/0/truncatedStackTraceElements").asInt())
                .isEqualTo(1);
        assertThat(compact.at("/otherThreadStates/WAITING").asInt()).isEqualTo(2);
        assertThat(compact.has("otherThreadGroups")).isFalse();
        assertThat(McpResponses.compactThreadDump(threadDump, 2, true)
                .at("/otherThreadGroups/0/threadCount").asInt()).isEqualTo(2);
    }

    // one message entry with two nested queries, and the same query again at top level
    private static final String ENTRIES = "{\"entries\":[{\"durationNanos\":2000000,"
            + "\"message\":\"render\",\"childEntries\":["
            + "{\"durationNanos\":1000000,\"queryMessage\":{\"queryText\":\"select a\"}},"
            + "{\"durationNanos\":3000000,\"queryMessage\":{\"queryText\":\"select a\"}}]},"
            + "{\"durationNanos\":500000,\"queryMessage\":{\"queryText\":\"select b\"}}]}";
}
