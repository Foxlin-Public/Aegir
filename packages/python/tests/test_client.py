import json
import unittest
from dataclasses import asdict

from foxlin_aegir_security import (
    AegirDiagnosticsHooks,
    AegirErrorCode,
    AegirSecurityClient,
    AegirSecurityError,
    BudgetEnvelopeOptions,
    BudgetExhaustedError,
    ExposureFindingCategory,
    ExposureFindingSeverity,
    InMemoryAgentToAgentProtocol,
    InMemoryBudgetEnvelopeService,
    IdentityActionStatus,
    IdentityActionType,
    IdentityGraphNodeType,
    PerformIdentityActionRequest,
    create_safe_envelope,
    sign_identity_token_payload,
    validate_safe_envelope,
    verify_identity_token_payload,
)


NOW = "2026-04-07T15:00:00Z"


class AegirSecurityClientTests(unittest.TestCase):
    def test_scan_identity(self):
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=self._transport)
        result = client.scanIdentity("developer:dev_123")
        self.assertEqual("developer:dev_123", result.subjectId)
        self.assertEqual("graph:developer:dev_123", result.graph.graphId)
        self.assertEqual(IdentityGraphNodeType.User, result.graph.nodes[0].nodeType)
        self.assertEqual(ExposureFindingCategory.WeakConnection, result.exposure.findings[0].category)
        self.assertEqual(ExposureFindingSeverity.Medium, result.exposure.findings[0].severity)
        self.assertEqual(IdentityActionType.VerifyConnection, result.actionHistory[0].actionType)
        self.assertEqual(IdentityActionStatus.Completed, result.actionHistory[0].status)

    def test_headers_are_attached(self):
        captured = {}

        def transport(url, method, headers, body):
            captured["headers"] = headers
            return 200, self._scan_payload()

        client = AegirSecurityClient(
            base_url="https://example.test/apis",
            config_key="config-key",
            developer_key="developer-key",
            transport=transport,
        )

        client.scanIdentity("developer:dev_123")
        self.assertEqual("config-key", captured["headers"]["X-Aegir-Config-Key"])
        self.assertEqual("developer-key", captured["headers"]["X-Aegir-Developer-Key"])

    def test_perform_action_posts_json(self):
        captured = {}

        def transport(url, method, headers, body):
            captured["method"] = method
            captured["body"] = json.loads(body)
            return 200, self._action_payload()

        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)
        client.performAction(
            PerformIdentityActionRequest(
                subjectId="developer:dev_123",
                actionType=IdentityActionType.VerifyConnection,
                targetNodeId="application:app_portal",
                reason="Testing.",
            )
        )

        self.assertEqual("POST", captured["method"])
        self.assertEqual("VerifyConnection", captured["body"]["actionType"])

    def test_raises_aegir_security_error(self):
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=lambda *_: (404, {"error": "not_found", "correlationId": "corr_123"}))
        with self.assertRaises(AegirSecurityError) as context:
            client.getExposureSummary("developer:dev_123")
        self.assertEqual(404, context.exception.status)
        self.assertEqual(AegirErrorCode.NotFound, context.exception.code)
        self.assertEqual("corr_123", context.exception.correlationId)

    def test_diagnostics_hooks_receive_events(self):
        logs = []
        metrics = []
        traces = []

        client = AegirSecurityClient(
            base_url="https://example.test/apis",
            diagnostics_hooks=AegirDiagnosticsHooks(log=logs.append, metric=metrics.append, trace=traces.append),
            transport=lambda *_: (200, self._graph_payload() | {"correlationId": "corr_diag"}),
        )

        client.getIdentityGraph("developer:dev_123")

        self.assertEqual("request.start", logs[0]["eventName"])
        self.assertEqual("aegir.client.request.duration", metrics[0]["metricName"])
        self.assertEqual("request.complete", traces[-1]["traceName"])
        self.assertEqual("corr_diag", traces[-1]["correlationId"])

    def test_safe_envelope_detects_tampering(self):
        envelope = create_safe_envelope("agent:test", '{"hello":"world"}')
        envelope.canonicalPayload = '{"hello":"tampered"}'
        result = validate_safe_envelope(envelope)
        self.assertFalse(result.isValid)
        self.assertEqual("payload_hash_mismatch", result.reason)

    def test_agent_to_agent_protocol_rejects_tampered_message(self):
        protocol = InMemoryAgentToAgentProtocol()
        message = protocol.send("agent:sender", "agent:recipient", "handoff", '{"hello":"world"}')
        message.envelope.canonicalPayload = '{"hello":"tampered"}'
        result = protocol.receive("agent:recipient", message.messageId)
        self.assertFalse(result.accepted)
        self.assertEqual("payload_hash_mismatch", result.reason)

    def test_budget_envelope_raises_when_exhausted(self):
        service = InMemoryBudgetEnvelopeService(BudgetEnvelopeOptions(identityScanLimit=1))
        service.consume("IdentityScan", "subject-1")
        with self.assertRaises(BudgetExhaustedError) as context:
            service.consume("IdentityScan", "subject-1")
        self.assertTrue(context.exception.envelope.isExhausted)

    def test_budget_options_defaults_and_wire_shape(self):
        service = InMemoryBudgetEnvelopeService()
        self.assertEqual(25, service.get_envelope("IdentityScan", "subject-1").limit)
        self.assertEqual(50, service.get_envelope("ExternalLookup", "subject-1").limit)
        self.assertEqual(10, service.get_envelope("ConnectionGraphRebuild", "subject-1").limit)

        options = BudgetEnvelopeOptions(identityScanLimit=2, externalLookupLimit=4, connectionGraphRebuildLimit=6, windowMs=30000)
        self.assertEqual(
            {
                "identityScanLimit": 2,
                "externalLookupLimit": 4,
                "connectionGraphRebuildLimit": 6,
                "windowMs": 30000,
            },
            asdict(options),
        )

    def test_dataclass_serialization_preserves_beta1_wire_shape(self):
        result = self._transport("https://example.test/apis/v1/security/scan/developer%3Adev_123", "GET", {}, None)[1]
        model = self._model_from_payload(result)
        payload = asdict(model)

        self.assertEqual("User", payload["graph"]["nodes"][0]["nodeType"])
        self.assertEqual("WeakConnection", payload["exposure"]["findings"][0]["category"])
        self.assertEqual("Medium", payload["exposure"]["findings"][0]["severity"])
        self.assertEqual("VerifyConnection", payload["actionHistory"][0]["actionType"])
        self.assertEqual("Completed", payload["actionHistory"][0]["status"])

    def test_identity_token_signature_detects_tampering(self):
        payload = b'{"userId":"user-1","trustLevel":4}'
        signature = sign_identity_token_payload(payload)
        self.assertEqual(64, len(signature))
        self.assertTrue(verify_identity_token_payload(payload, signature))
        self.assertFalse(verify_identity_token_payload(b'{"userId":"user-2","trustLevel":4}', signature))

    def _transport(self, url, method, headers, body):
        if url.endswith("/v1/security/scan/developer%3Adev_123"):
            return 200, self._scan_payload()
        if url.endswith("/v1/security/graphs/developer%3Adev_123"):
            return 200, self._graph_payload()
        if url.endswith("/v1/security/exposure/developer%3Adev_123"):
            return 200, self._exposure_payload()
        if url.endswith("/v1/security/actions") and method == "POST":
            return 200, self._action_payload()
        if url.endswith("/v1/security/actions/history/developer%3Adev_123"):
            return 200, [self._action_payload()]
        return 404, {"error": "not_found"}

    def _scan_payload(self):
        return {
            "subjectId": "developer:dev_123",
            "graph": self._graph_payload(),
            "exposure": self._exposure_payload(),
            "actionHistory": [self._action_payload()],
        }

    def _graph_payload(self):
        return {
            "graphId": "graph:developer:dev_123",
            "generatedAtUtc": NOW,
            "scores": {
                "exposureScore": 0.15,
                "trustScore": 0.92,
                "connectionClarityScore": 0.88,
            },
            "nodes": [
                {
                    "nodeId": "developer:dev_123",
                    "nodeType": "User",
                    "displayName": "dev_123@example.com",
                    "status": "active",
                    "trustTier": "high",
                    "observedAtUtc": NOW,
                    "lastVerifiedAtUtc": NOW,
                    "metadata": {},
                }
            ],
            "edges": [],
            "metadata": {},
        }

    def _exposure_payload(self):
        return {
            "graphId": "graph:developer:dev_123",
            "generatedAtUtc": NOW,
            "exposureScore": 0.15,
            "findings": [
                {
                    "findingId": "finding_001",
                    "category": "WeakConnection",
                    "severity": "Medium",
                    "summary": "Weak service linkage.",
                    "nodeId": "developer:dev_123",
                    "edgeId": None,
                    "metadata": {},
                }
            ],
            "summaryText": "Low exposure posture.",
        }

    def _action_payload(self):
        return {
            "actionId": "action_001",
            "subjectId": "developer:dev_123",
            "actionType": "VerifyConnection",
            "status": "Completed",
            "targetNodeId": "application:app_portal",
            "reason": "Python sample validation.",
            "requestedAtUtc": NOW,
            "reversedAtUtc": None,
            "reverseReason": None,
            "metadata": {},
        }

    def _model_from_payload(self, payload):
        from foxlin_aegir_security import ScanIdentityResult

        return ScanIdentityResult.from_json(payload)


if __name__ == "__main__":
    unittest.main()


class AegirAiSurfaceTests(unittest.TestCase):
    """Contract cover for the agent, transaction and protected-messaging capabilities.

    End-to-end behaviour is proved by ``tests/live_flow.py`` against a real host. These pin the
    paths, bodies and credential handling so a drift in the wire contract fails here first.

    Written as a ``TestCase`` rather than bare functions on purpose: the repository runs
    ``python -m unittest discover``, which silently ignores plain test functions.
    """

    @staticmethod
    def _recording_transport(status=200, payload=None):
        captured = {}

        def transport(url, method, headers, body):
            captured["url"] = url
            captured["method"] = method
            captured["headers"] = headers
            captured["body"] = json.loads(body) if body else None
            return status, payload if payload is not None else {}

        return transport, captured

    def test_create_transaction_posts_the_declared_action(self):
        transport, captured = self._recording_transport(
            payload={"transactionId": "AGTX-0011", "status": "Created"}
        )
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)

        result = client.createTransaction("ai.provider.invoke", targetResourceId="res_1")

        self.assertEqual(captured["url"], "https://example.test/apis/v1/transactions")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["body"]["declaredAction"], "ai.provider.invoke")
        self.assertEqual(captured["body"]["targetResourceId"], "res_1")
        self.assertEqual(result["transactionId"], "AGTX-0011")

    def test_agent_key_grant_presents_the_key_then_uses_the_bearer_token(self):
        transport, captured = self._recording_transport(
            payload={"access_token": "agent.token.value", "token_type": "Bearer", "scopes": []}
        )
        client = AegirSecurityClient(
            base_url="https://example.test/apis", developer_key="dev_1:secret", transport=transport
        )

        client.useAgentKey("agt_1:agent-secret")

        self.assertEqual(captured["headers"]["X-Aegir-Agent-Key"], "agt_1:agent-secret")
        self.assertEqual(captured["body"]["grantType"], "agent_key")

        # From here the agent token is the credential. The developer key must not keep
        # travelling alongside it — a request carrying both would authenticate as the wrong
        # principal, and the agent's narrower scopes would be silently bypassed.
        client.getTransaction("AGTX-0011")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer agent.token.value")
        self.assertNotIn("X-Aegir-Developer-Key", captured["headers"])

    def test_send_agent_message_posts_transaction_recipient_action_and_payload(self):
        transport, captured = self._recording_transport(
            payload={"transactionId": "AGTX-0011", "envelope": {"envelopeId": "env_1"}}
        )
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)

        client.sendAgentMessage("AGTX-0011", "agt_beta", "agent.finding.share", "cGF5bG9hZA==")

        self.assertEqual(captured["url"], "https://example.test/apis/v1/ai/messages")
        self.assertEqual(
            captured["body"],
            {
                "transactionId": "AGTX-0011",
                "recipientAgentId": "agt_beta",
                "action": "agent.finding.share",
                "payload": "cGF5bG9hZA==",
            },
        )

    def test_bind_provider_never_returns_the_credential_it_sent(self):
        transport, captured = self._recording_transport(
            payload={
                "bindingId": "pbnd_1",
                "agentPrincipalId": "agt_1",
                "providerId": "openai",
                "allowedModelIds": [],
                "createdAtUtc": "2026-08-09T00:00:00Z",
                "revokedAtUtc": None,
            }
        )
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)

        binding = client.bindProvider(
            "agt_1", "openai", "sk-secret", allowedModelIds=["gpt-4o-mini"]
        )

        self.assertEqual(captured["url"], "https://example.test/apis/v1/agents/agt_1/providers")
        self.assertEqual(captured["body"]["apiKey"], "sk-secret")

        # A binding can be replaced but never read back.
        self.assertNotIn("apiKey", binding)

    def test_invoke_provider_reports_a_vendor_failure_as_data(self):
        transport, _ = self._recording_transport(
            payload={
                "invocationId": "pinv_1",
                "transactionId": "AGTX-0011",
                "providerId": "openai",
                "modelId": "gpt-4o-mini",
                "agentPrincipalId": "agt_1",
                "requestDigest": "abc",
                "succeeded": False,
                "content": None,
                "stopReason": None,
                "usage": None,
                "errorKind": "RateLimited",
                "errorMessage": "slow down",
                "errorRetryable": True,
            }
        )
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)

        result = client.invokeProvider(
            "AGTX-0011", "openai", "gpt-4o-mini", [{"role": "user", "content": "hi"}]
        )

        # A vendor failure is not an exception: it is recorded exactly like a success, which is
        # what keeps a failed call as auditable as a completed one.
        self.assertFalse(result["succeeded"])
        self.assertEqual(result["errorKind"], "RateLimited")
        self.assertTrue(result["errorRetryable"])

    def test_server_error_codes_outside_the_common_set_are_preserved(self):
        # Regression: the client coerced every code into AegirErrorCode and collapsed anything
        # unrecognised to unknown_error, so a caller could not tell an envelope rejection from
        # any other failure. The JS client always kept the raw code; these now agree.
        transport, _ = self._recording_transport(
            status=403, payload={"error": "envelope_rejected", "status": "Replayed"}
        )
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)

        with self.assertRaises(AegirSecurityError) as caught:
            client.receiveAgentMessage({"transactionId": "AGTX-0011", "envelope": {}})

        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(caught.exception.code, "envelope_rejected")

    def test_known_error_codes_still_resolve_to_the_enum(self):
        transport, _ = self._recording_transport(status=403, payload={"error": "forbidden"})
        client = AegirSecurityClient(base_url="https://example.test/apis", transport=transport)

        with self.assertRaises(AegirSecurityError) as caught:
            client.getTransaction("AGTX-0011")

        self.assertEqual(caught.exception.code, AegirErrorCode.Forbidden)
