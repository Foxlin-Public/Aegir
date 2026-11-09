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
        char[] password=System.getenv("AEGIR_JAVA_TEST_KEYSTORE_PASS").toCharArray();java.security.KeyStore store=java.security.KeyStore.getInstance("PKCS12");try(java.io.InputStream in=java.nio.file.Files.newInputStream(java.nio.file.Path.of(args[0]))){store.load(in,password);}javax.net.ssl.KeyManagerFactory keys=javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());keys.init(store,password);java.util.Arrays.fill(password,'\0');javax.net.ssl.SSLContext tls=javax.net.ssl.SSLContext.getInstance("TLS");tls.init(keys.getKeyManagers(),null,null);
        com.sun.net.httpserver.HttpsServer server=com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress("127.0.0.1",0),0);server.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(tls));
        String pin=AuthorizationIntegration.hex(java.security.MessageDigest.getInstance("SHA-256").digest(store.getCertificate("aegir-test").getEncoded()));
        server.createContext("/apis/v1/security/scan/developer:dev_123", exchange -> respond(exchange, 200, "{\"subjectId\":\"developer:dev_123\",\"graph\":{\"graphId\":\"graph:developer:dev_123\",\"generatedAtUtc\":\"2026-04-07T15:00:00Z\",\"nodes\":[{\"nodeId\":\"developer:dev_123\",\"nodeType\":\"Developer\",\"displayName\":\"Dev 123\",\"status\":\"active\",\"trustTier\":\"verified\",\"metadata\":{\"region\":\"us\"},\"observedAtUtc\":\"2026-04-07T14:59:00Z\",\"lastVerifiedAtUtc\":null}],\"edges\":[{\"edgeId\":\"edge:1\",\"edgeType\":\"Owns\",\"fromNodeId\":\"developer:dev_123\",\"toNodeId\":\"app:1\",\"status\":\"active\",\"trustWeight\":0.97,\"evidenceType\":\"registration\",\"reason\":\"owner of record\",\"observedAtUtc\":\"2026-04-07T14:59:30Z\",\"lastVerifiedAtUtc\":\"2026-04-07T15:00:00Z\",\"metadata\":{\"source\":\"fixture\"}}],\"scores\":{\"exposureScore\":0.15,\"trustScore\":0.92,\"connectionClarityScore\":0.88},\"metadata\":{\"source\":\"test\"}},\"exposure\":{\"graphId\":\"graph:developer:dev_123\",\"generatedAtUtc\":\"2026-04-07T15:00:00Z\",\"exposureScore\":0.15,\"findings\":[{\"findingId\":\"finding:1\",\"category\":\"WeakConnection\",\"severity\":\"Medium\",\"summary\":\"Weak service linkage.\",\"nodeId\":\"developer:dev_123\",\"edgeId\":\"edge:1\",\"metadata\":{\"hint\":\"rotate\"}}],\"summaryText\":\"Low exposure posture.\"},\"actionHistory\":[{\"actionId\":\"action:1\",\"subjectId\":\"developer:dev_123\",\"actionType\":\"LockIdentity\",\"status\":\"Completed\",\"targetNodeId\":\"developer:dev_123\",\"reason\":\"risk response\",\"requestedAtUtc\":\"2026-04-07T15:01:00Z\",\"reversedAtUtc\":null,\"reverseReason\":null,\"metadata\":{\"operator\":\"test\"}}]}"));
        server.createContext("/apis/v1/security/exposure/developer:dev_123", exchange -> respond(exchange, 404, "{\"error\":\"not_found\"}"));
        server.start();

        try
        {
            String baseUrl = "https://127.0.0.1:" + server.getAddress().getPort() + "/apis";
            List<AegirDiagnosticsHooks.LogEntry> logs = new ArrayList<>();
            List<AegirDiagnosticsHooks.MetricEvent> metrics = new ArrayList<>();
            List<AegirDiagnosticsHooks.TraceEvent> traces = new ArrayList<>();
            AegirSecurityClient client = AegirSecurityClient.pinnedLoopbackDevelopment(baseUrl,"developer-key",pin,java.time.Duration.ofSeconds(2),new AegirDiagnosticsHooks(logs::add,metrics::add,traces::add));

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

            client.close();
            testR004();
            System.out.println("PASS Java offline client suite; R004 four contract groups with shared SHA256/rejection fixtures");
        }
        finally
        {
            server.stop(0);
        }
    }

    @SuppressWarnings("deprecation")
    private static void testR004() throws Exception
    {
        @SuppressWarnings("unchecked")
        Map<String,Object> vectors = (Map<String,Object>) JsonSupport.parse(java.nio.file.Files.readString(java.nio.file.Path.of("tests/crypto-vectors.json")));
        @SuppressWarnings("unchecked")
        List<Map<String,Object>> hashes = (List<Map<String,Object>>) vectors.get("sha256");
        for (Map<String,Object> vector : hashes)
            if (!vector.get("digest").equals(PortableSecurity.computePayloadDigest(fromHex((String)vector.get("hex"))))) throw new AssertionError("SHA256 mismatch");
        if (PortableSecurity.computePayloadDigest("{\"a\":1,\"b\":2}".getBytes(java.nio.charset.StandardCharsets.UTF_8)).equals(PortableSecurity.computePayloadDigest("{\"b\":2,\"a\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8)))) throw new AssertionError("serialization changed");
        @SuppressWarnings("unchecked")
        Map<String,Object> historical=(Map<String,Object>) vectors.get("historicalKeyless");
        byte[] payload=fromHex((String)historical.get("payloadHex"));
        String[] kinds={"Challenge","ProofReceipt","IdentityToken"};
        String[] keys={"challenge","proofReceipt","identityToken"};
        for(int i=0;i<kinds.length;i++)
        {
            java.lang.reflect.Method sign=PortableSecurity.class.getMethod("sign"+kinds[i]+"Payload",byte[].class);
            try {sign.invoke(null,payload);throw new AssertionError("retired signer accepted");}
            catch(java.lang.reflect.InvocationTargetException ex) {if (!(ex.getCause() instanceof UnsupportedOperationException)) throw ex;}
            java.lang.reflect.Method verify=PortableSecurity.class.getMethod("verify"+kinds[i]+"Payload",byte[].class,byte[].class);
            byte[] legacy=fromHex((String)historical.get(keys[i]));
            for(byte[] proof:new byte[][]{legacy,null,new byte[0],new byte[64],java.util.Arrays.copyOf(legacy,65)})
                if((Boolean)verify.invoke(null,payload,proof)) throw new AssertionError("retired verifier accepted");
        }
        PortableSecurity.SafeEnvelopeValidationResult unsigned=PortableSecurity.validateSafeEnvelope(PortableSecurity.createSafeEnvelope("test","abc",null));
        if(!unsigned.isValid() || unsigned.isAuthenticated() || !"integrity_only".equals(unsigned.getReason())) throw new AssertionError("integrity classification");
        for(String algorithm:new String[]{"ML-DSA-65","hybrid-beta1","","invalid"})
            for(String key:new String[]{"unknown","substituted-device",""})
                for(byte[] proof:new byte[][]{null,new byte[0],fromHex((String)historical.get("challenge")),new byte[3309]})
                {
                    PortableSecurity.TrustCoreSignatureEnvelope signature=new PortableSecurity.TrustCoreSignatureEnvelope(key,new PortableSecurity.TrustCoreAlgorithmDescriptor(algorithm,true),proof);
                    PortableSecurity.SafeEnvelopeValidationResult result=PortableSecurity.validateSafeEnvelope(PortableSecurity.createSafeEnvelope("test","abc",signature));
                    if(result.isValid() || result.isAuthenticated() || !"unsupported_signature".equals(result.getReason())) throw new AssertionError("accepted unsupported signature");
                }
        PortableSecurity.InMemoryAgentToAgentProtocol queue=new PortableSecurity.InMemoryAgentToAgentProtocol();
        PortableSecurity.AgentToAgentMessageRecord message=queue.send("agent:sender","agent:recipient","test","abc",null,new PortableSecurity.TrustCoreSignatureEnvelope("unknown",new PortableSecurity.TrustCoreAlgorithmDescriptor("ML-DSA-65",false),new byte[3309]));
        PortableSecurity.AgentToAgentReceiveResult received=queue.receive("agent:recipient",message.getMessageId());
        if(received.isAccepted() || !"unsupported_signature".equals(received.getReason())) throw new AssertionError("queue accepted authority");
    }

    private static byte[] fromHex(String input)
    {
        byte[] data=new byte[input.length()/2];
        for(int i=0;i<data.length;i++) data[i]=(byte)Integer.parseInt(input.substring(i*2,i*2+2),16);
        return data;
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
