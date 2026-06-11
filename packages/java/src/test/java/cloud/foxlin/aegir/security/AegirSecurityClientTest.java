package cloud.foxlin.aegir.security;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class AegirSecurityClientTest
{
    public static void main(String[] args) throws Exception
    {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/apis/v1/security/scan/developer:dev_123", exchange -> respond(exchange, 200, "{\"subjectId\":\"developer:dev_123\",\"graph\":{\"graphId\":\"graph:developer:dev_123\",\"generatedAtUtc\":\"2026-04-07T15:00:00Z\",\"nodes\":[{\"nodeId\":\"developer:dev_123\",\"nodeType\":\"Developer\",\"displayName\":\"Dev 123\",\"status\":\"active\",\"trustTier\":\"verified\",\"metadata\":{\"region\":\"us\"},\"observedAtUtc\":\"2026-04-07T14:59:00Z\",\"lastVerifiedAtUtc\":null}],\"edges\":[{\"edgeId\":\"edge:1\",\"edgeType\":\"Owns\",\"fromNodeId\":\"developer:dev_123\",\"toNodeId\":\"app:1\",\"status\":\"active\",\"trustWeight\":0.97,\"evidenceType\":\"registration\",\"reason\":\"owner of record\",\"observedAtUtc\":\"2026-04-07T14:59:30Z\",\"lastVerifiedAtUtc\":\"2026-04-07T15:00:00Z\",\"metadata\":{\"source\":\"fixture\"}}],\"scores\":{\"exposureScore\":0.15,\"trustScore\":0.92,\"connectionClarityScore\":0.88},\"metadata\":{\"source\":\"test\"}},\"exposure\":{\"graphId\":\"graph:developer:dev_123\",\"generatedAtUtc\":\"2026-04-07T15:00:00Z\",\"exposureScore\":0.15,\"findings\":[{\"findingId\":\"finding:1\",\"category\":\"WeakConnection\",\"severity\":\"Medium\",\"summary\":\"Weak service linkage.\",\"nodeId\":\"developer:dev_123\",\"edgeId\":\"edge:1\",\"metadata\":{\"hint\":\"rotate\"}}],\"summaryText\":\"Low exposure posture.\"},\"actionHistory\":[{\"actionId\":\"action:1\",\"subjectId\":\"developer:dev_123\",\"actionType\":\"LockIdentity\",\"status\":\"Completed\",\"targetNodeId\":\"developer:dev_123\",\"reason\":\"risk response\",\"requestedAtUtc\":\"2026-04-07T15:01:00Z\",\"reversedAtUtc\":null,\"reverseReason\":null,\"metadata\":{\"operator\":\"test\"}}]}"));
        server.createContext("/apis/v1/security/exposure/developer:dev_123", exchange -> respond(exchange, 404, "{\"error\":\"not_found\"}"));
        server.start();

        try
        {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/apis";
            List<AegirDiagnosticsHooks.LogEntry> logs = new ArrayList<>();
            List<AegirDiagnosticsHooks.MetricEvent> metrics = new ArrayList<>();
            List<AegirDiagnosticsHooks.TraceEvent> traces = new ArrayList<>();
            AegirSecurityClient client = new AegirSecurityClient(
                baseUrl,
                "config-key",
                "developer-key",
                HttpClient.newHttpClient(),
                new AegirDiagnosticsHooks(logs::add, metrics::add, traces::add));

            SecurityModels.ScanIdentityResult result = client.scanIdentity("developer:dev_123");
            if (!"developer:dev_123".equals(result.getSubjectId()))
            {
                throw new AssertionError("Expected subjectId to round-trip.");
            }
            if (result.getGraph().getNodes().get(0).getNodeType() != SecurityModels.IdentityGraphNodeType.Developer)
            {
                throw new AssertionError("Expected typed identity graph node.");
            }
            if (result.getGraph().getEdges().get(0).getEdgeType() != SecurityModels.IdentityGraphEdgeType.Owns)
            {
                throw new AssertionError("Expected typed identity graph edge.");
            }
            if (!"0.88".equals(result.getGraph().getScores().getConnectionClarityScore().toString()))
            {
                throw new AssertionError("Expected typed graph scores.");
            }
            if (result.getExposure().getFindings().get(0).getCategory() != SecurityModels.ExposureFindingCategory.WeakConnection)
            {
                throw new AssertionError("Expected typed exposure finding category.");
            }
            if (result.getExposure().getFindings().get(0).getSeverity() != SecurityModels.ExposureFindingSeverity.Medium)
            {
                throw new AssertionError("Expected typed exposure finding severity.");
            }
            if (result.getActionHistory().get(0).getActionType() != SecurityModels.IdentityActionType.LockIdentity)
            {
                throw new AssertionError("Expected typed action type.");
            }
            if (result.getActionHistory().get(0).getStatus() != SecurityModels.IdentityActionStatus.Completed)
            {
                throw new AssertionError("Expected typed action status.");
            }
            Object actionMetadata = result.getActionHistory().get(0).getPayload().get("metadata");
            Object operator = actionMetadata instanceof Map ? ((Map<?, ?>) actionMetadata).get("operator") : null;
            if (!"test".equals(operator))
            {
                throw new AssertionError("Expected action payload to preserve metadata.");
            }

            PerformIdentityActionRequest actionRequest =
                new PerformIdentityActionRequest("developer:dev_123", SecurityModels.IdentityActionType.VerifyConnection, "edge:1", "refresh evidence");
            if (!"VerifyConnection".equals(actionRequest.toMap().get("actionType")))
            {
                throw new AssertionError("Expected typed action request to serialize as the C# enum name.");
            }

            try
            {
                client.getExposureSummary("developer:dev_123");
                throw new AssertionError("Expected AegirSecurityError.");
            }
            catch (AegirSecurityError ex)
            {
                if (ex.getStatus() != 404)
                {
                    throw new AssertionError("Expected status 404.");
                }
                if (!"not_found".equals(ex.getCode()))
                {
                    throw new AssertionError("Expected code not_found.");
                }
                if (ex.getErrorCode() != AegirErrorCode.NOT_FOUND)
                {
                    throw new AssertionError("Expected typed error code.");
                }
            }

            if (!"request.start".equals(logs.get(0).eventName()))
            {
                throw new AssertionError("Expected diagnostics log entry.");
            }
            if (!"aegir.client.request.duration".equals(metrics.get(0).metricName()))
            {
                throw new AssertionError("Expected diagnostics metric entry.");
            }
            if (!"request.complete".equals(traces.get(1).traceName()))
            {
                throw new AssertionError("Expected diagnostics trace completion.");
            }

            PortableSecurity.SafeEnvelopeRecord envelope =
                PortableSecurity.createSafeEnvelope("agent:test", "{\"hello\":\"world\"}", null);
            PortableSecurity.SafeEnvelopeRecord tampered =
                new PortableSecurity.SafeEnvelopeRecord(
                    envelope.getEnvelopeId(),
                    envelope.getPayloadType(),
                    "{\"hello\":\"tampered\"}",
                    envelope.getPayloadHash(),
                    envelope.getCreatedAtUtc(),
                    envelope.getSignatureEnvelope());
            PortableSecurity.SafeEnvelopeValidationResult validation = PortableSecurity.validateSafeEnvelope(tampered);
            if (validation.isValid() || !"payload_hash_mismatch".equals(validation.getReason()))
            {
                throw new AssertionError("Expected tampered envelope to fail.");
            }

            PortableSecurity.InMemoryAgentToAgentProtocol protocol = new PortableSecurity.InMemoryAgentToAgentProtocol();
            PortableSecurity.AgentToAgentMessageRecord message =
                protocol.send("agent:sender", "agent:recipient", "handoff", "{\"hello\":\"world\"}", null, null);
            protocol.getInbox("agent:recipient").set(
                0,
                new PortableSecurity.AgentToAgentMessageRecord(
                    message.getMessageId(),
                    message.getSenderAgentId(),
                    message.getRecipientAgentId(),
                    message.getMessageType(),
                    message.getCorrelationId(),
                    tampered,
                    message.getSentAtUtc(),
                    null));
            PortableSecurity.AgentToAgentReceiveResult receiveResult = protocol.receive("agent:recipient", message.getMessageId());
            if (receiveResult.isAccepted() || !"payload_hash_mismatch".equals(receiveResult.getReason()))
            {
                throw new AssertionError("Expected tampered A2A message to fail.");
            }

            PortableSecurity.InMemoryBudgetEnvelopeService budgetService =
                new PortableSecurity.InMemoryBudgetEnvelopeService(new PortableSecurity.BudgetEnvelopeOptions(10, 50, 10, 60_000L));
            try
            {
                for (int i = 0; i < 11; i++)
                {
                    budgetService.consume("IdentityScan", "subject-1");
                }
                throw new AssertionError("Expected BudgetExhaustedError.");
            }
            catch (PortableSecurity.BudgetExhaustedError ex)
            {
                if (!ex.getEnvelope().isExhausted())
                {
                    throw new AssertionError("Expected exhausted envelope.");
                }
            }

            PortableSecurity.InMemoryBudgetEnvelopeService defaultBudgetService = new PortableSecurity.InMemoryBudgetEnvelopeService();
            if (defaultBudgetService.getEnvelope("IdentityScan", "subject-1").getLimit() != 25)
            {
                throw new AssertionError("Expected default identity-scan budget limit 25.");
            }
            if (defaultBudgetService.getEnvelope("ExternalLookup", "subject-1").getLimit() != 50)
            {
                throw new AssertionError("Expected default external-lookup budget limit 50.");
            }
            if (defaultBudgetService.getEnvelope("ConnectionGraphRebuild", "subject-1").getLimit() != 10)
            {
                throw new AssertionError("Expected default rebuild budget limit 10.");
            }

            String modelJson = JsonSupport.stringify(result.toMap());
            if (!modelJson.contains("\"nodeType\":\"Developer\"") ||
                !modelJson.contains("\"edgeType\":\"Owns\"") ||
                !modelJson.contains("\"category\":\"WeakConnection\"") ||
                !modelJson.contains("\"status\":\"Completed\""))
            {
                throw new AssertionError("Expected model JSON to preserve Beta 1 wire shape.");
            }

            byte[] payload = "{\"userId\":\"user-1\",\"trustLevel\":4}".getBytes();
            byte[] signature = PortableSecurity.signIdentityTokenPayload(payload);
            if (signature.length != 64)
            {
                throw new AssertionError("Expected 64-byte identity-token signature.");
            }
            if (!PortableSecurity.verifyIdentityTokenPayload(payload, signature))
            {
                throw new AssertionError("Expected identity-token signature to verify.");
            }
            if (PortableSecurity.verifyIdentityTokenPayload("{\"userId\":\"user-2\",\"trustLevel\":4}".getBytes(), signature))
            {
                throw new AssertionError("Expected tampered identity-token payload to fail.");
            }
        }
        finally
        {
            server.stop(0);
        }
    }

    private static void respond(HttpExchange exchange, int statusCode, String body) throws IOException
    {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("X-Correlation-Id", "corr_test");
        exchange.sendResponseHeaders(statusCode, body.getBytes().length);
        try (OutputStream stream = exchange.getResponseBody())
        {
            stream.write(body.getBytes());
        }
    }
}
