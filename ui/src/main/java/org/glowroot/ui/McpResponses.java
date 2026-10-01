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

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

// Reshapes the UI's json responses for mcp clients (LLM agents): smaller, self-describing and
// with explicit units.
//
// Note: the embedded collector jar is processed by proguard, which recomputes stack map frames
// without seeing the shaded jackson classes, so no local variable (or ternary) here may hold two
// different jackson node types (they would be merged into java.lang.Object and fail verification).
final class McpResponses {

    private static final JsonNodeFactory nodes = JsonNodeFactory.instance;

    private static final double NANOS_PER_MILLI = 1000000.0;

    // largest integer exactly representable as a double
    private static final double MAX_EXACT_LONG = 9007199254740992.0;

    private McpResponses() {}

    // ---- numbers ----

    // the UI serializes aggregate totals as doubles (e.g. 2.85202499E10 nanoseconds), rewrite
    // integral values (and anything in nanoseconds, bytes or counts) as plain integers
    static void normalizeNumbers(JsonNode node) {
        if (node instanceof ObjectNode) {
            ObjectNode objectNode = (ObjectNode) node;
            List<String> fieldNames = Lists.newArrayList(objectNode.fieldNames());
            for (String fieldName : fieldNames) {
                JsonNode value = objectNode.get(fieldName);
                if (value.isFloatingPointNumber()) {
                    double d = value.asDouble();
                    if (isIntegral(d) || hasIntegralUnit(fieldName)) {
                        objectNode.put(fieldName, Math.round(d));
                    }
                } else {
                    normalizeNumbers(value);
                }
            }
        } else if (node instanceof ArrayNode) {
            ArrayNode arrayNode = (ArrayNode) node;
            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode element = arrayNode.get(i);
                if (element.isFloatingPointNumber()) {
                    double d = element.asDouble();
                    if (isIntegral(d)) {
                        arrayNode.set(i, LongNode.valueOf(Math.round(d)));
                    }
                } else {
                    normalizeNumbers(element);
                }
            }
        }
    }

    private static boolean isIntegral(double d) {
        return !Double.isInfinite(d) && Math.abs(d) < MAX_EXACT_LONG && d == Math.rint(d);
    }

    private static boolean hasIntegralUnit(String fieldName) {
        return fieldName.endsWith("Nanos") || fieldName.endsWith("Bytes")
                || fieldName.endsWith("Count");
    }

    // percentile values are in nanoseconds in the UI response
    static void addPercentileMillis(JsonNode node) {
        for (JsonNode percentileValue : node.path("mergedAggregate").path("percentileValues")) {
            if (percentileValue instanceof ObjectNode) {
                ObjectNode objectNode = (ObjectNode) percentileValue;
                JsonNode value = objectNode.remove("value");
                if (value != null) {
                    objectNode.put("valueNanos", Math.round(value.asDouble()));
                    objectNode.put("valueMillis", millis(value.asDouble()));
                }
            }
        }
    }

    static double millis(double nanos) {
        return Math.round(nanos / NANOS_PER_MILLI * 1000) / 1000.0;
    }

    // ---- thread profiles ----

    // summary of a (transaction or trace) thread profile, as an agent needs it: sample count,
    // hottest frames (inclusive and self), the hot path down to where it branches, and leaf thread
    // states
    static ObjectNode summarizeProfile(JsonNode profile, int topFrames, double hotPathMinPercent,
            List<String> collapsedFramePrefixes) {
        ObjectNode summary = nodes.objectNode();
        long totalSamples = 0;
        for (JsonNode rootNode : profile.path("rootNodes")) {
            totalSamples += rootNode.path("sampleCount").asLong();
        }
        summary.put("sampleCount", totalSamples);
        if (totalSamples == 0) {
            return summary;
        }
        Map<String, Long> inclusive = Maps.newHashMap();
        Map<String, Long> self = Maps.newHashMap();
        Map<String, Long> leafStates = Maps.newTreeMap();
        for (JsonNode rootNode : profile.path("rootNodes")) {
            collectFrames(rootNode, Sets.<String>newHashSet(), inclusive, self, leafStates);
        }
        summary.set("topFramesInclusive", topFrames(inclusive, totalSamples, topFrames));
        summary.set("topFramesSelf", topFrames(self, totalSamples, topFrames));
        ObjectNode leafStatesNode = summary.putObject("leafThreadStates");
        for (Map.Entry<String, Long> entry : leafStates.entrySet()) {
            leafStatesNode.put(entry.getKey(), entry.getValue());
        }
        summary.set("hotPath",
                hotPath(profile, totalSamples, hotPathMinPercent, collapsedFramePrefixes));
        return summary;
    }

    private static void collectFrames(JsonNode node, Set<String> ancestorFrames,
            Map<String, Long> inclusive, Map<String, Long> self, Map<String, Long> leafStates) {
        String frame = node.path("stackTraceElement").asText();
        long sampleCount = node.path("sampleCount").asLong();
        boolean added = ancestorFrames.add(frame);
        if (added) {
            // count recursive frames only once per sample
            increment(inclusive, frame, sampleCount);
        }
        long childSamples = 0;
        for (JsonNode childNode : node.path("childNodes")) {
            childSamples += childNode.path("sampleCount").asLong();
            collectFrames(childNode, ancestorFrames, inclusive, self, leafStates);
        }
        long selfSamples = sampleCount - childSamples;
        if (selfSamples > 0) {
            increment(self, frame, selfSamples);
            String state = node.path("leafThreadState").asText("");
            increment(leafStates, state.isEmpty() ? "UNKNOWN" : state, selfSamples);
        }
        if (added) {
            ancestorFrames.remove(frame);
        }
    }

    private static void increment(Map<String, Long> map, String key, long delta) {
        Long current = map.get(key);
        map.put(key, current == null ? delta : current + delta);
    }

    private static ArrayNode topFrames(Map<String, Long> samples, long totalSamples, int limit) {
        List<Map.Entry<String, Long>> entries = Lists.newArrayList(samples.entrySet());
        Collections.sort(entries,
                (left, right) -> Long.compare(right.getValue(), left.getValue()));
        ArrayNode frames = nodes.arrayNode();
        for (Map.Entry<String, Long> entry : entries.subList(0, Math.min(limit, entries.size()))) {
            ObjectNode frame = frames.addObject();
            frame.put("frame", entry.getKey());
            frame.put("sampleCount", entry.getValue());
            frame.put("percent", percent(entry.getValue(), totalSamples));
        }
        return frames;
    }

    // follows the heaviest child from the root, reporting branch points (where the heaviest child
    // carries clearly less than its parent) with their main alternatives; collapsed frames (e.g.
    // the servlet container trunk) are walked through but not reported
    private static ArrayNode hotPath(JsonNode profile, long totalSamples,
            double hotPathMinPercent, List<String> collapsedFramePrefixes) {
        ArrayNode path = nodes.arrayNode();
        JsonNode current = heaviest(profile.path("rootNodes"));
        int depth = 0;
        int collapsed = 0;
        while (current != null
                && percent(current.path("sampleCount").asLong(), totalSamples)
                        >= hotPathMinPercent) {
            String frame = current.path("stackTraceElement").asText();
            long sampleCount = current.path("sampleCount").asLong();
            JsonNode children = current.path("childNodes");
            JsonNode next = heaviest(children);
            boolean branch = next != null && children.size() > 1
                    && next.path("sampleCount").asLong() < sampleCount * 0.8;
            if (isCollapsed(frame, collapsedFramePrefixes) && !branch) {
                collapsed++;
            } else {
                ObjectNode step = path.addObject();
                step.put("depth", depth);
                step.put("frame", frame);
                step.put("sampleCount", sampleCount);
                step.put("percent", percent(sampleCount, totalSamples));
                if (collapsed > 0) {
                    step.put("collapsedFramesAbove", collapsed);
                    collapsed = 0;
                }
                String state = current.path("leafThreadState").asText("");
                if (!state.isEmpty() && children.size() == 0) {
                    step.put("leafThreadState", state);
                }
                if (branch) {
                    ArrayNode alternatives = step.putArray("branches");
                    for (JsonNode child : sortedBySamples(children, 4)) {
                        ObjectNode alternative = alternatives.addObject();
                        alternative.put("frame", child.path("stackTraceElement").asText());
                        alternative.put("sampleCount", child.path("sampleCount").asLong());
                        alternative.put("percent",
                                percent(child.path("sampleCount").asLong(), totalSamples));
                    }
                }
            }
            current = next;
            depth++;
        }
        return path;
    }

    private static boolean isCollapsed(String frame, List<String> collapsedFramePrefixes) {
        for (String prefix : collapsedFramePrefixes) {
            if (frame.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static JsonNode heaviest(JsonNode children) {
        JsonNode heaviest = null;
        long max = -1;
        for (JsonNode child : children) {
            long sampleCount = child.path("sampleCount").asLong();
            if (sampleCount > max) {
                max = sampleCount;
                heaviest = child;
            }
        }
        return heaviest;
    }

    private static List<JsonNode> sortedBySamples(JsonNode children, int limit) {
        List<JsonNode> sorted = Lists.newArrayList(children);
        Collections.sort(sorted, (left, right) -> Long.compare(
                right.path("sampleCount").asLong(), left.path("sampleCount").asLong()));
        return sorted.subList(0, Math.min(limit, sorted.size()));
    }

    private static double percent(long part, long total) {
        return total == 0 ? 0 : Math.round(part * 1000.0 / total) / 10.0;
    }

    // ---- trace entries ----

    // flattens the entry tree (pre-order, with depth), then filters, pages or aggregates it, so
    // that a trace with thousands of entries can be explored piece by piece
    static ObjectNode pageEntries(JsonNode entriesResponse, double minDurationMillis,
            String kind, String messageContains, boolean aggregate, int offset, int limit) {
        List<ObjectNode> flattened = Lists.newArrayList();
        flatten(entriesResponse.path("entries"), 0, flattened);
        List<ObjectNode> matching = Lists.newArrayList();
        for (ObjectNode entry : flattened) {
            if (matches(entry, minDurationMillis, kind, messageContains)) {
                matching.add(entry);
            }
        }
        ObjectNode result = nodes.objectNode();
        result.put("totalEntries", flattened.size());
        result.put("matchingEntries", matching.size());
        if (aggregate) {
            ArrayNode groups = result.putArray("groups");
            List<ObjectNode> aggregated = aggregate(matching);
            for (ObjectNode group : aggregated.subList(0, Math.min(limit, aggregated.size()))) {
                groups.add(group);
            }
            result.put("moreGroups", aggregated.size() > limit);
            return result;
        }
        int from = Math.min(offset, matching.size());
        int to = Math.min(from + limit, matching.size());
        result.put("offset", from);
        ArrayNode entries = result.putArray("entries");
        for (ObjectNode entry : matching.subList(from, to)) {
            entries.add(entry);
        }
        result.put("hasMore", to < matching.size());
        return result;
    }

    private static void flatten(JsonNode entries, int depth, List<ObjectNode> flattened) {
        for (JsonNode entry : entries) {
            if (!(entry instanceof ObjectNode)) {
                continue;
            }
            ObjectNode copy = ((ObjectNode) entry).deepCopy();
            JsonNode childEntries = copy.remove("childEntries");
            copy.put("depth", depth);
            flattened.add(copy);
            if (childEntries != null) {
                flatten(childEntries, depth + 1, flattened);
            }
        }
    }

    private static boolean matches(ObjectNode entry, double minDurationMillis, String kind,
            String messageContains) {
        if (entry.path("durationNanos").asDouble() < minDurationMillis * NANOS_PER_MILLI) {
            return false;
        }
        boolean query = entry.has("queryMessage");
        if (kind.equals("query") && !query || kind.equals("other") && query) {
            return false;
        }
        return messageContains.isEmpty()
                || text(entry).toLowerCase().contains(messageContains.toLowerCase());
    }

    private static String text(ObjectNode entry) {
        JsonNode queryMessage = entry.get("queryMessage");
        if (queryMessage != null) {
            return queryMessage.path("prefix").asText() + queryMessage.path("queryText").asText();
        }
        return entry.path("message").asText();
    }

    // groups entries by query text (or message), sorted by total duration
    private static List<ObjectNode> aggregate(List<ObjectNode> entries) {
        Map<String, ObjectNode> groups = Maps.newLinkedHashMap();
        for (ObjectNode entry : entries) {
            JsonNode queryMessage = entry.get("queryMessage");
            String key = queryMessage == null ? "message:" + entry.path("message").asText()
                    : "query:" + queryMessage.path("queryText").asText();
            ObjectNode group = groups.get(key);
            long durationNanos = Math.round(entry.path("durationNanos").asDouble());
            if (group == null) {
                group = nodes.objectNode();
                if (queryMessage == null) {
                    group.put("message", entry.path("message").asText());
                } else {
                    group.put("queryText", queryMessage.path("queryText").asText());
                }
                group.put("count", 0);
                group.put("totalDurationNanos", 0L);
                group.put("maxDurationNanos", 0L);
                groups.put(key, group);
            }
            group.put("count", group.path("count").asInt() + 1);
            group.put("totalDurationNanos", group.path("totalDurationNanos").asLong()
                    + durationNanos);
            group.put("maxDurationNanos",
                    Math.max(group.path("maxDurationNanos").asLong(), durationNanos));
        }
        List<ObjectNode> sorted = Lists.newArrayList(groups.values());
        Collections.sort(sorted, (left, right) -> Long.compare(
                right.path("totalDurationNanos").asLong(),
                left.path("totalDurationNanos").asLong()));
        return sorted;
    }

    // ---- thread dump ----

    // keeps threads running a transaction in full, and groups the other threads by state and
    // top of stack, so that the dump of a busy application server stays readable
    static ObjectNode compactThreadDump(JsonNode threadDump, int maxStackDepth,
            boolean includeOtherThreads) {
        ObjectNode result = nodes.objectNode();
        ArrayNode transactions = result.putArray("transactions");
        for (JsonNode transaction : threadDump.path("transactions")) {
            if (!(transaction instanceof ObjectNode)) {
                continue;
            }
            ObjectNode copy = ((ObjectNode) transaction).deepCopy();
            for (JsonNode thread : copy.path("threads")) {
                truncateStack(thread, maxStackDepth);
            }
            transactions.add(copy);
        }
        Map<String, Long> states = Maps.newTreeMap();
        ArrayNode otherThreadGroups = nodes.arrayNode();
        for (JsonNode group : threadDump.path("unmatchedThreadsByStackTrace")) {
            JsonNode first = group.path(0);
            String state = first.path("state").asText();
            increment(states, state, group.size());
            if (includeOtherThreads) {
                ObjectNode groupNode = otherThreadGroups.addObject();
                groupNode.put("threadCount", group.size());
                groupNode.put("state", state);
                ArrayNode names = groupNode.putArray("threadNames");
                Iterator<JsonNode> i = group.elements();
                for (int n = 0; n < 5 && i.hasNext(); n++) {
                    names.add(i.next().path("name").asText());
                }
                ArrayNode stack = groupNode.putArray("stackTraceElements");
                int n = 0;
                for (JsonNode element : first.path("stackTraceElements")) {
                    if (n++ >= maxStackDepth) {
                        break;
                    }
                    stack.add(element.asText());
                }
            }
        }
        ObjectNode statesNode = result.putObject("otherThreadStates");
        for (Map.Entry<String, Long> entry : states.entrySet()) {
            statesNode.put(entry.getKey(), entry.getValue());
        }
        if (includeOtherThreads) {
            result.set("otherThreadGroups", otherThreadGroups);
        }
        JsonNode deadlockedCycles = threadDump.get("deadlockedCycles");
        if (deadlockedCycles != null) {
            result.set("deadlockedCycles", deadlockedCycles);
        }
        return result;
    }

    private static void truncateStack(JsonNode thread, int maxStackDepth) {
        JsonNode stackNode = thread.path("stackTraceElements");
        if (stackNode instanceof ArrayNode && stackNode.size() > maxStackDepth) {
            ArrayNode stack = (ArrayNode) stackNode;
            int removed = stack.size() - maxStackDepth;
            while (stack.size() > maxStackDepth) {
                stack.remove(stack.size() - 1);
            }
            ((ObjectNode) thread).put("truncatedStackTraceElements", removed);
        }
    }
}
