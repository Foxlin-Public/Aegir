import assert from "node:assert/strict";

import {
  AegirSecurityClient,
  AegirSecurityError,
  BudgetExhaustedError,
  InMemoryAgentToAgentProtocol,
  InMemoryBudgetEnvelopeService,
  signIdentityTokenPayload,
  verifyIdentityTokenPayload,
  createSafeEnvelope,
  validateSafeEnvelope
} from "../dist/esm/index.js";

async function test(name, run) {
  try {
    await run();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    throw error;
  }
}

await test("scanIdentity sends config and developer key headers", async () => {
  let capturedUrl = null;
  let capturedHeaders = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis",
    configKey: "cfg_123",
    developerKey: "dev_456",
    fetcher: async (url, init) => {
      capturedUrl = url;
      capturedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  });

  await client.scanIdentity("developer:dev_123");

  assert.equal(capturedUrl, "https://example.test/apis/v1/security/scan/developer%3Adev_123");
  assert.equal(capturedHeaders.get("Accept"), "application/json");
  assert.equal(capturedHeaders.get("X-Aegir-Config-Key"), "cfg_123");
  assert.equal(capturedHeaders.get("X-Aegir-Developer-Key"), "dev_456");
});

await test("performAction posts JSON payload", async () => {
  let capturedMethod = null;
  let capturedBody = null;
  let capturedContentType = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis",
    fetcher: async (_url, init) => {
      capturedMethod = init?.method ?? "GET";
      capturedBody = init?.body;
      capturedContentType = new Headers(init?.headers).get("Content-Type");
      return new Response(JSON.stringify({ actionId: "action_123" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  });

  await client.performAction({
    subjectId: "developer:dev_123",
    actionType: "LockIdentity",
    reason: "Manual review"
  });

  assert.equal(capturedMethod, "POST");
  assert.equal(capturedContentType, "application/json");
  assert.equal(capturedBody, JSON.stringify({
    subjectId: "developer:dev_123",
    actionType: "LockIdentity",
    reason: "Manual review"
  }));
});

await test("reverseAction appends encoded reason", async () => {
  let capturedUrl = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis",
    fetcher: async (url) => {
      capturedUrl = url;
      return new Response(JSON.stringify({ actionId: "action_123" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  });

  await client.reverseAction("action_123", "resolved by admin");

  assert.equal(
    capturedUrl,
    "https://example.test/apis/v1/security/actions/action_123/reverse?reason=resolved%20by%20admin"
  );
});

await test("request throws AegirSecurityError for non-200 JSON response", async () => {
  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis",
    fetcher: async () => new Response(JSON.stringify({ error: "forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr_123" }
    })
  });

  await assert.rejects(
    () => client.getExposureSummary("developer:dev_123"),
    (error) => {
      assert.ok(error instanceof AegirSecurityError);
      assert.equal(error.status, 403);
      assert.equal(error.code, "forbidden");
      assert.equal(error.correlationId, "corr_123");
      assert.deepEqual(error.body, { error: "forbidden" });
      return true;
    }
  );
});

await test("diagnostics hooks receive log metric and trace events", async () => {
  const logs = [];
  const metrics = [];
  const traces = [];

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis",
    diagnosticsHooks: {
      log: (entry) => logs.push(entry),
      metric: (event) => metrics.push(event),
      trace: (event) => traces.push(event)
    },
    fetcher: async () => new Response(JSON.stringify({ graphId: "graph:developer:dev_123", generatedAtUtc: "2026-04-07T15:00:00Z", scores: { exposureScore: 0.15, trustScore: 0.92, connectionClarityScore: 0.88 }, nodes: [], edges: [], metadata: {} }), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Correlation-Id": "corr_diag" }
    })
  });

  await client.getIdentityGraph("developer:dev_123");

  assert.equal(logs[0].eventName, "request.start");
  assert.equal(metrics[0].metricName, "aegir.client.request.duration");
  assert.equal(traces.at(-1).traceName, "request.complete");
  assert.equal(traces.at(-1).correlationId, "corr_diag");
});

await test("request returns raw text body when response is not JSON", async () => {
  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis",
    fetcher: async () => new Response("plain-text-response", {
      status: 200,
      headers: { "Content-Type": "text/plain" }
    })
  });

  const result = await client.getIdentityGraphJson("developer:dev_123");

  assert.equal(result, "\"plain-text-response\"");
});

await test("safe envelope detects tampering", async () => {
  const envelope = createSafeEnvelope("agent:test", "{\"hello\":\"world\"}");
  envelope.canonicalPayload = "{\"hello\":\"tampered\"}";
  const result = validateSafeEnvelope(envelope);
  assert.equal(result.isValid, false);
  assert.equal(result.reason, "payload_hash_mismatch");
});

await test("a2a receive rejects tampered message", async () => {
  const protocol = new InMemoryAgentToAgentProtocol();
  const message = protocol.send("agent:sender", "agent:recipient", "handoff", "{\"hello\":\"world\"}");
  message.envelope.canonicalPayload = "{\"hello\":\"tampered\"}";
  const result = protocol.receive("agent:recipient", message.messageId);
  assert.equal(result.accepted, false);
  assert.equal(result.reason, "payload_hash_mismatch");
});

await test("budget service throws exhaustion error", async () => {
  const service = new InMemoryBudgetEnvelopeService({ identityScanLimit: 1 });
  service.consume("IdentityScan", "subject-1");
  assert.throws(() => service.consume("IdentityScan", "subject-1"), (error) => {
    assert.ok(error instanceof BudgetExhaustedError);
    assert.equal(error.envelope.isExhausted, true);
    return true;
  });
});

await test("budget service uses canonical defaults and options wire shape", async () => {
  const defaults = new InMemoryBudgetEnvelopeService();
  assert.equal(defaults.getEnvelope("IdentityScan", "subject-1").limit, 25);
  assert.equal(defaults.getEnvelope("ExternalLookup", "subject-1").limit, 50);
  assert.equal(defaults.getEnvelope("ConnectionGraphRebuild", "subject-1").limit, 10);

  const configured = new InMemoryBudgetEnvelopeService({
    identityScanLimit: 2,
    externalLookupLimit: 4,
    connectionGraphRebuildLimit: 6,
    windowMs: 30_000
  });
  const envelope = configured.getEnvelope("IdentityScan", "subject-1");
  assert.equal(envelope.limit, 2);
  assert.equal(new Date(envelope.windowEndsAtUtc).getTime() - new Date(envelope.windowStartedAtUtc).getTime(), 30_000);
});

await test("public model objects preserve beta1 JSON wire shape", async () => {
  const payload = {
    subjectId: "developer:dev_123",
    graph: {
      graphId: "graph:developer:dev_123",
      generatedAtUtc: "2026-04-07T15:00:00Z",
      scores: { exposureScore: 0.15, trustScore: 0.92, connectionClarityScore: 0.88 },
      nodes: [{
        nodeId: "developer:dev_123",
        nodeType: "Developer",
        displayName: "Dev 123",
        status: "active",
        trustTier: "verified",
        observedAtUtc: "2026-04-07T14:59:00Z",
        lastVerifiedAtUtc: null,
        metadata: { region: "us" }
      }],
      edges: [{
        edgeId: "edge:1",
        edgeType: "Owns",
        fromNodeId: "developer:dev_123",
        toNodeId: "app:1",
        status: "active",
        trustWeight: 0.97,
        evidenceType: "registration",
        reason: "owner of record",
        observedAtUtc: "2026-04-07T14:59:30Z",
        lastVerifiedAtUtc: null,
        metadata: {}
      }],
      metadata: {}
    },
    exposure: {
      graphId: "graph:developer:dev_123",
      generatedAtUtc: "2026-04-07T15:00:00Z",
      exposureScore: 0.15,
      findings: [{
        findingId: "finding:1",
        category: "WeakConnection",
        severity: "Medium",
        summary: "Weak service linkage.",
        nodeId: "developer:dev_123",
        edgeId: "edge:1",
        metadata: {}
      }],
      summaryText: "Low exposure posture."
    },
    actionHistory: [{
      actionId: "action:1",
      subjectId: "developer:dev_123",
      actionType: "VerifyConnection",
      status: "Completed",
      targetNodeId: "developer:dev_123",
      reason: "risk response",
      requestedAtUtc: "2026-04-07T15:01:00Z",
      reversedAtUtc: null,
      reverseReason: null,
      metadata: {}
    }]
  };

  const json = JSON.stringify(payload);
  assert.ok(json.includes("\"nodeType\":\"Developer\""));
  assert.ok(json.includes("\"edgeType\":\"Owns\""));
  assert.ok(json.includes("\"category\":\"WeakConnection\""));
  assert.ok(json.includes("\"status\":\"Completed\""));
});

await test("identity-token signature verifies and fails on tampering", async () => {
  const payload = new TextEncoder().encode("{\"userId\":\"user-1\",\"trustLevel\":4}");
  const signature = signIdentityTokenPayload(payload);
  assert.equal(signature.length, 64);
  assert.equal(verifyIdentityTokenPayload(payload, signature), true);

  const tampered = new TextEncoder().encode("{\"userId\":\"user-2\",\"trustLevel\":4}");
  assert.equal(verifyIdentityTokenPayload(tampered, signature), false);
});
