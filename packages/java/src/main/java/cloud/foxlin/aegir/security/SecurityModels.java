package cloud.foxlin.aegir.security;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public final class SecurityModels
{
    private SecurityModels()
    {
    }

    public enum IdentityActionType
    {
        LockIdentity,
        DisconnectService,
        VerifyConnection,
        RequestClarity
    }

    public enum IdentityActionStatus
    {
        Completed,
        Reversed
    }

    public enum IdentityGraphNodeType
    {
        Platform,
        Developer,
        DeveloperKey,
        Application,
        Environment,
        User,
        Device,
        Credential,
        Challenge,
        Token,
        AuditAnchor,
        PolicyScope,
        ExternalService
    }

    public enum IdentityGraphEdgeType
    {
        Owns,
        Issued,
        Registered,
        BelongsTo,
        AuthorizedFor,
        ScopedTo,
        Uses,
        PresentedBy,
        DerivedFrom,
        ApprovedBy,
        RevokedBy,
        AnchoredBy,
        ConnectedTo,
        ObservedOn
    }

    public enum ExposureFindingCategory
    {
        WeakConnection,
        UnknownConnection,
        StaleCredential,
        HighRiskLinkage
    }

    public enum ExposureFindingSeverity
    {
        Low,
        Medium,
        High
    }

    public static final class IdentityGraphScores
    {
        private final BigDecimal exposureScore;
        private final BigDecimal trustScore;
        private final BigDecimal connectionClarityScore;

        public IdentityGraphScores(BigDecimal exposureScore, BigDecimal trustScore, BigDecimal connectionClarityScore)
        {
            this.exposureScore = exposureScore;
            this.trustScore = trustScore;
            this.connectionClarityScore = connectionClarityScore;
        }

        IdentityGraphScores(Map<String, Object> payload)
        {
            this(decimalValue(payload.get("exposureScore")), decimalValue(payload.get("trustScore")), decimalValue(payload.get("connectionClarityScore")));
        }

        public BigDecimal getExposureScore()
        {
            return exposureScore;
        }

        public BigDecimal getTrustScore()
        {
            return trustScore;
        }

        public BigDecimal getConnectionClarityScore()
        {
            return connectionClarityScore;
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("exposureScore", exposureScore);
            payload.put("trustScore", trustScore);
            payload.put("connectionClarityScore", connectionClarityScore);
            return payload;
        }
    }

    public static final class IdentityGraphNode
    {
        private final String nodeId;
        private final IdentityGraphNodeType nodeType;
        private final String displayName;
        private final String status;
        private final String trustTier;
        private final Map<String, String> metadata;
        private final OffsetDateTime observedAtUtc;
        private final OffsetDateTime lastVerifiedAtUtc;

        public IdentityGraphNode(
            String nodeId,
            IdentityGraphNodeType nodeType,
            String displayName,
            String status,
            String trustTier,
            Map<String, String> metadata,
            OffsetDateTime observedAtUtc,
            OffsetDateTime lastVerifiedAtUtc)
        {
            this.nodeId = nodeId;
            this.nodeType = nodeType;
            this.displayName = displayName;
            this.status = status;
            this.trustTier = trustTier;
            this.metadata = immutableStringMap(metadata);
            this.observedAtUtc = observedAtUtc;
            this.lastVerifiedAtUtc = lastVerifiedAtUtc;
        }

        IdentityGraphNode(Map<String, Object> payload)
        {
            this(
                stringValue(payload.get("nodeId")),
                enumValue(IdentityGraphNodeType.class, payload.get("nodeType")),
                stringValue(payload.get("displayName")),
                stringValue(payload.get("status")),
                stringValue(payload.get("trustTier")),
                stringMap(payload.get("metadata")),
                dateTimeValue(payload.get("observedAtUtc")),
                dateTimeValue(payload.get("lastVerifiedAtUtc")));
        }

        public String getNodeId()
        {
            return nodeId;
        }

        public IdentityGraphNodeType getNodeType()
        {
            return nodeType;
        }

        public String getDisplayName()
        {
            return displayName;
        }

        public String getStatus()
        {
            return status;
        }

        public String getTrustTier()
        {
            return trustTier;
        }

        public Map<String, String> getMetadata()
        {
            return metadata;
        }

        public OffsetDateTime getObservedAtUtc()
        {
            return observedAtUtc;
        }

        public OffsetDateTime getLastVerifiedAtUtc()
        {
            return lastVerifiedAtUtc;
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("nodeId", nodeId);
            payload.put("nodeType", nodeType == null ? null : nodeType.name());
            payload.put("displayName", displayName);
            payload.put("status", status);
            payload.put("trustTier", trustTier);
            payload.put("metadata", metadata);
            payload.put("observedAtUtc", dateTimeText(observedAtUtc));
            payload.put("lastVerifiedAtUtc", dateTimeText(lastVerifiedAtUtc));
            return payload;
        }
    }

    public static final class IdentityGraphEdge
    {
        private final String edgeId;
        private final IdentityGraphEdgeType edgeType;
        private final String fromNodeId;
        private final String toNodeId;
        private final String status;
        private final BigDecimal trustWeight;
        private final String evidenceType;
        private final String reason;
        private final OffsetDateTime observedAtUtc;
        private final OffsetDateTime lastVerifiedAtUtc;
        private final Map<String, String> metadata;

        public IdentityGraphEdge(
            String edgeId,
            IdentityGraphEdgeType edgeType,
            String fromNodeId,
            String toNodeId,
            String status,
            BigDecimal trustWeight,
            String evidenceType,
            String reason,
            OffsetDateTime observedAtUtc,
            OffsetDateTime lastVerifiedAtUtc,
            Map<String, String> metadata)
        {
            this.edgeId = edgeId;
            this.edgeType = edgeType;
            this.fromNodeId = fromNodeId;
            this.toNodeId = toNodeId;
            this.status = status;
            this.trustWeight = trustWeight;
            this.evidenceType = evidenceType;
            this.reason = reason;
            this.observedAtUtc = observedAtUtc;
            this.lastVerifiedAtUtc = lastVerifiedAtUtc;
            this.metadata = immutableStringMap(metadata);
        }

        IdentityGraphEdge(Map<String, Object> payload)
        {
            this(
                stringValue(payload.get("edgeId")),
                enumValue(IdentityGraphEdgeType.class, payload.get("edgeType")),
                stringValue(payload.get("fromNodeId")),
                stringValue(payload.get("toNodeId")),
                stringValue(payload.get("status")),
                decimalValue(payload.get("trustWeight")),
                stringValue(payload.get("evidenceType")),
                stringValue(payload.get("reason")),
                dateTimeValue(payload.get("observedAtUtc")),
                dateTimeValue(payload.get("lastVerifiedAtUtc")),
                stringMap(payload.get("metadata")));
        }

        public String getEdgeId()
        {
            return edgeId;
        }

        public IdentityGraphEdgeType getEdgeType()
        {
            return edgeType;
        }

        public String getFromNodeId()
        {
            return fromNodeId;
        }

        public String getToNodeId()
        {
            return toNodeId;
        }

        public String getStatus()
        {
            return status;
        }

        public BigDecimal getTrustWeight()
        {
            return trustWeight;
        }

        public String getEvidenceType()
        {
            return evidenceType;
        }

        public String getReason()
        {
            return reason;
        }

        public OffsetDateTime getObservedAtUtc()
        {
            return observedAtUtc;
        }

        public OffsetDateTime getLastVerifiedAtUtc()
        {
            return lastVerifiedAtUtc;
        }

        public Map<String, String> getMetadata()
        {
            return metadata;
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("edgeId", edgeId);
            payload.put("edgeType", edgeType == null ? null : edgeType.name());
            payload.put("fromNodeId", fromNodeId);
            payload.put("toNodeId", toNodeId);
            payload.put("status", status);
            payload.put("trustWeight", trustWeight);
            payload.put("evidenceType", evidenceType);
            payload.put("reason", reason);
            payload.put("observedAtUtc", dateTimeText(observedAtUtc));
            payload.put("lastVerifiedAtUtc", dateTimeText(lastVerifiedAtUtc));
            payload.put("metadata", metadata);
            return payload;
        }
    }

    public static final class IdentityGraphSnapshot
    {
        private final String graphId;
        private final OffsetDateTime generatedAtUtc;
        private final List<IdentityGraphNode> nodes;
        private final List<IdentityGraphEdge> edges;
        private final IdentityGraphScores scores;
        private final Map<String, String> metadata;

        public IdentityGraphSnapshot(
            String graphId,
            OffsetDateTime generatedAtUtc,
            List<IdentityGraphNode> nodes,
            List<IdentityGraphEdge> edges,
            IdentityGraphScores scores,
            Map<String, String> metadata)
        {
            this.graphId = graphId;
            this.generatedAtUtc = generatedAtUtc;
            this.nodes = immutableList(nodes);
            this.edges = immutableList(edges);
            this.scores = scores;
            this.metadata = immutableStringMap(metadata);
        }

        IdentityGraphSnapshot(Map<String, Object> payload)
        {
            this(
                stringValue(payload.get("graphId")),
                dateTimeValue(payload.get("generatedAtUtc")),
                modelList(payload.get("nodes"), IdentityGraphNode::new),
                modelList(payload.get("edges"), IdentityGraphEdge::new),
                new IdentityGraphScores(asMap(payload.get("scores"))),
                stringMap(payload.get("metadata")));
        }

        public String getGraphId()
        {
            return graphId;
        }

        public OffsetDateTime getGeneratedAtUtc()
        {
            return generatedAtUtc;
        }

        public List<IdentityGraphNode> getNodes()
        {
            return nodes;
        }

        public List<IdentityGraphEdge> getEdges()
        {
            return edges;
        }

        public IdentityGraphScores getScores()
        {
            return scores;
        }

        public Map<String, String> getMetadata()
        {
            return metadata;
        }

        public Map<String, Object> getPayload()
        {
            return toMap();
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("graphId", graphId);
            payload.put("generatedAtUtc", dateTimeText(generatedAtUtc));
            payload.put("nodes", mapList(nodes, IdentityGraphNode::toMap));
            payload.put("edges", mapList(edges, IdentityGraphEdge::toMap));
            payload.put("scores", scores == null ? null : scores.toMap());
            payload.put("metadata", metadata);
            return payload;
        }
    }

    public static final class ExposureFinding
    {
        private final String findingId;
        private final ExposureFindingCategory category;
        private final ExposureFindingSeverity severity;
        private final String summary;
        private final String nodeId;
        private final String edgeId;
        private final Map<String, String> metadata;

        public ExposureFinding(
            String findingId,
            ExposureFindingCategory category,
            ExposureFindingSeverity severity,
            String summary,
            String nodeId,
            String edgeId,
            Map<String, String> metadata)
        {
            this.findingId = findingId;
            this.category = category;
            this.severity = severity;
            this.summary = summary;
            this.nodeId = nodeId;
            this.edgeId = edgeId;
            this.metadata = immutableStringMap(metadata);
        }

        ExposureFinding(Map<String, Object> payload)
        {
            this(
                stringValue(payload.get("findingId")),
                enumValue(ExposureFindingCategory.class, payload.get("category")),
                enumValue(ExposureFindingSeverity.class, payload.get("severity")),
                stringValue(payload.get("summary")),
                stringValue(payload.get("nodeId")),
                stringValue(payload.get("edgeId")),
                stringMap(payload.get("metadata")));
        }

        public String getFindingId()
        {
            return findingId;
        }

        public ExposureFindingCategory getCategory()
        {
            return category;
        }

        public ExposureFindingSeverity getSeverity()
        {
            return severity;
        }

        public String getSummary()
        {
            return summary;
        }

        public String getNodeId()
        {
            return nodeId;
        }

        public String getEdgeId()
        {
            return edgeId;
        }

        public Map<String, String> getMetadata()
        {
            return metadata;
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("findingId", findingId);
            payload.put("category", category == null ? null : category.name());
            payload.put("severity", severity == null ? null : severity.name());
            payload.put("summary", summary);
            payload.put("nodeId", nodeId);
            payload.put("edgeId", edgeId);
            payload.put("metadata", metadata);
            return payload;
        }
    }

    public static final class ExposureSummary
    {
        private final String graphId;
        private final OffsetDateTime generatedAtUtc;
        private final BigDecimal exposureScore;
        private final List<ExposureFinding> findings;
        private final String summaryText;

        public ExposureSummary(
            String graphId,
            OffsetDateTime generatedAtUtc,
            BigDecimal exposureScore,
            List<ExposureFinding> findings,
            String summaryText)
        {
            this.graphId = graphId;
            this.generatedAtUtc = generatedAtUtc;
            this.exposureScore = exposureScore;
            this.findings = immutableList(findings);
            this.summaryText = summaryText;
        }

        ExposureSummary(Map<String, Object> payload)
        {
            this(
                stringValue(payload.get("graphId")),
                dateTimeValue(payload.get("generatedAtUtc")),
                decimalValue(payload.get("exposureScore")),
                modelList(payload.get("findings"), ExposureFinding::new),
                stringValue(payload.get("summaryText")));
        }

        public String getGraphId()
        {
            return graphId;
        }

        public OffsetDateTime getGeneratedAtUtc()
        {
            return generatedAtUtc;
        }

        public BigDecimal getExposureScore()
        {
            return exposureScore;
        }

        public List<ExposureFinding> getFindings()
        {
            return findings;
        }

        public String getSummaryText()
        {
            return summaryText;
        }

        public Map<String, Object> getPayload()
        {
            return toMap();
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("graphId", graphId);
            payload.put("generatedAtUtc", dateTimeText(generatedAtUtc));
            payload.put("exposureScore", exposureScore);
            payload.put("findings", mapList(findings, ExposureFinding::toMap));
            payload.put("summaryText", summaryText);
            return payload;
        }
    }

    public static final class IdentityActionRecord
    {
        private final String actionId;
        private final String subjectId;
        private final IdentityActionType actionType;
        private final IdentityActionStatus status;
        private final String targetNodeId;
        private final String reason;
        private final OffsetDateTime requestedAtUtc;
        private final OffsetDateTime reversedAtUtc;
        private final String reverseReason;
        private final Map<String, String> metadata;

        public IdentityActionRecord(
            String actionId,
            String subjectId,
            IdentityActionType actionType,
            IdentityActionStatus status,
            String targetNodeId,
            String reason,
            OffsetDateTime requestedAtUtc,
            OffsetDateTime reversedAtUtc,
            String reverseReason,
            Map<String, String> metadata)
        {
            this.actionId = actionId;
            this.subjectId = subjectId;
            this.actionType = actionType;
            this.status = status;
            this.targetNodeId = targetNodeId;
            this.reason = reason;
            this.requestedAtUtc = requestedAtUtc;
            this.reversedAtUtc = reversedAtUtc;
            this.reverseReason = reverseReason;
            this.metadata = immutableStringMap(metadata);
        }

        IdentityActionRecord(Map<String, Object> payload)
        {
            this(
                stringValue(payload.get("actionId")),
                stringValue(payload.get("subjectId")),
                enumValue(IdentityActionType.class, payload.get("actionType")),
                enumValue(IdentityActionStatus.class, payload.get("status")),
                stringValue(payload.get("targetNodeId")),
                stringValue(payload.get("reason")),
                dateTimeValue(payload.get("requestedAtUtc")),
                dateTimeValue(payload.get("reversedAtUtc")),
                stringValue(payload.get("reverseReason")),
                stringMap(payload.get("metadata")));
        }

        public String getActionId()
        {
            return actionId;
        }

        public String getSubjectId()
        {
            return subjectId;
        }

        public IdentityActionType getActionType()
        {
            return actionType;
        }

        public IdentityActionStatus getStatus()
        {
            return status;
        }

        public String getTargetNodeId()
        {
            return targetNodeId;
        }

        public String getReason()
        {
            return reason;
        }

        public OffsetDateTime getRequestedAtUtc()
        {
            return requestedAtUtc;
        }

        public OffsetDateTime getReversedAtUtc()
        {
            return reversedAtUtc;
        }

        public String getReverseReason()
        {
            return reverseReason;
        }

        public Map<String, String> getMetadata()
        {
            return metadata;
        }

        public Map<String, Object> getPayload()
        {
            return toMap();
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("actionId", actionId);
            payload.put("subjectId", subjectId);
            payload.put("actionType", actionType == null ? null : actionType.name());
            payload.put("status", status == null ? null : status.name());
            payload.put("targetNodeId", targetNodeId);
            payload.put("reason", reason);
            payload.put("requestedAtUtc", dateTimeText(requestedAtUtc));
            payload.put("reversedAtUtc", dateTimeText(reversedAtUtc));
            payload.put("reverseReason", reverseReason);
            payload.put("metadata", metadata);
            return payload;
        }
    }

    public static final class ScanIdentityResult
    {
        private final String subjectId;
        private final IdentityGraphSnapshot graph;
        private final ExposureSummary exposure;
        private final List<IdentityActionRecord> actionHistory;

        public ScanIdentityResult(
            String subjectId,
            IdentityGraphSnapshot graph,
            ExposureSummary exposure,
            List<IdentityActionRecord> actionHistory)
        {
            this.subjectId = subjectId;
            this.graph = graph;
            this.exposure = exposure;
            this.actionHistory = immutableList(actionHistory);
        }

        ScanIdentityResult(Map<String, Object> payload, IdentityGraphSnapshot graph, ExposureSummary exposure, List<IdentityActionRecord> actionHistory)
        {
            this(stringValue(payload.get("subjectId")), graph, exposure, actionHistory);
        }

        public String getSubjectId()
        {
            return subjectId;
        }

        public IdentityGraphSnapshot getGraph()
        {
            return graph;
        }

        public ExposureSummary getExposure()
        {
            return exposure;
        }

        public List<IdentityActionRecord> getActionHistory()
        {
            return actionHistory;
        }

        public Map<String, Object> toMap()
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("subjectId", subjectId);
            payload.put("graph", graph == null ? null : graph.toMap());
            payload.put("exposure", exposure == null ? null : exposure.toMap());
            payload.put("actionHistory", mapList(actionHistory, IdentityActionRecord::toMap));
            return payload;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value)
    {
        return (Map<String, Object>) value;
    }

    private static String stringValue(Object value)
    {
        return value == null ? null : value.toString();
    }

    private static BigDecimal decimalValue(Object value)
    {
        if (value == null)
        {
            return null;
        }

        if (value instanceof BigDecimal)
        {
            return (BigDecimal) value;
        }

        if (value instanceof Number)
        {
            return new BigDecimal(value.toString());
        }

        return new BigDecimal(value.toString());
    }

    private static OffsetDateTime dateTimeValue(Object value)
    {
        String text = stringValue(value);
        return text == null || text.isBlank() ? null : OffsetDateTime.parse(text);
    }

    private static String dateTimeText(OffsetDateTime value)
    {
        return value == null ? null : value.toString();
    }

    private static <T extends Enum<T>> T enumValue(Class<T> type, Object value)
    {
        String text = stringValue(value);
        return text == null || text.isBlank() ? null : Enum.valueOf(type, text);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> stringMap(Object value)
    {
        if (value == null)
        {
            return Collections.emptyMap();
        }

        Map<String, Object> source = (Map<String, Object>) value;
        Map<String, String> converted = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : source.entrySet())
        {
            converted.put(entry.getKey(), entry.getValue() == null ? null : entry.getValue().toString());
        }

        return converted;
    }

    private static Map<String, String> immutableStringMap(Map<String, String> value)
    {
        if (value == null || value.isEmpty())
        {
            return Collections.emptyMap();
        }

        return Collections.unmodifiableMap(new LinkedHashMap<>(value));
    }

    private static <T> List<T> immutableList(List<T> value)
    {
        if (value == null || value.isEmpty())
        {
            return Collections.emptyList();
        }

        return Collections.unmodifiableList(new ArrayList<>(value));
    }

    @SuppressWarnings("unchecked")
    private static <T> List<T> modelList(Object value, Function<Map<String, Object>, T> factory)
    {
        if (value == null)
        {
            return Collections.emptyList();
        }

        List<T> items = new ArrayList<>();
        for (Object item : (List<Object>) value)
        {
            items.add(factory.apply((Map<String, Object>) item));
        }

        return items;
    }

    private static <T> List<Object> mapList(List<T> values, Function<T, Map<String, Object>> mapper)
    {
        List<Object> items = new ArrayList<>();
        if (values == null)
        {
            return items;
        }

        for (T value : values)
        {
            items.add(mapper.apply(value));
        }

        return items;
    }
}
