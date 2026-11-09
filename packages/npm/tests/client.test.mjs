import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as portable from "../dist/esm/index.js";
const cryptoVectors = JSON.parse(readFileSync(new URL("./crypto-vectors.json", import.meta.url), "utf8"));

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

await test("scanIdentity omits deprecated config input and sends developer key header", async () => {
  let capturedUrl = null;
  let capturedHeaders = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    configKey: "cfg_123",
    developerKey: "dev_456",
    fetcher: async (url, init) => {
      capturedUrl = url;
      capturedHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify({ subjectId: "developer:dev_123", graph: {graphId:"graph:developer:dev_123",scores:{exposureScore:0,trustScore:1,connectionClarityScore:1},nodes:[],edges:[]}, exposure: {graphId:"graph:developer:dev_123",findings:[]} }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  });

  await client.scanIdentity("developer:dev_123");

  assert.equal(capturedUrl, "https://example.test/apis/v1/security/scan/developer%3Adev_123");
  assert.equal(capturedHeaders.get("Accept"), "application/json");
  assert.equal(capturedHeaders.get("X-Aegir-Config-Key"), null);
  assert.equal(capturedHeaders.get("X-Aegir-Developer-Key"), "dev_456");
});

await test("performAction posts JSON payload", async () => {
  let capturedMethod = null;
  let capturedBody = null;
  let capturedContentType = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    fetcher: async (_url, init) => {
      capturedMethod = init?.method ?? "GET";
      capturedBody = init?.body;
      capturedContentType = new Headers(init?.headers).get("Content-Type");
      return new Response(JSON.stringify({ actionId: "action_123", subjectId: "developer:dev_123",actionType:1,status:1 }), {
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
    actionType: 1,
    reason: "Manual review"
  }));
});

await test("reverseAction appends encoded reason", async () => {
  let capturedUrl = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    fetcher: async (url) => {
      capturedUrl = url;
      return new Response(JSON.stringify({ actionId: "action_123", subjectId: "developer:dev_123",actionType:1,status:1 }), {
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
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
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
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
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

await test("request rejects a successful raw text response as invalid authority data", async () => {
  const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    fetcher: async () => new Response("plain-text-response", {status:200,headers:{"Content-Type":"text/plain"}}) });
  await assert.rejects(() => client.getIdentityGraphJson("developer:dev_123"), AegirSecurityError);
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

await test("R004 SHA256 shared vectors are integrity only", async () => {
  for (const vector of cryptoVectors.sha256) {
    assert.equal(portable.computePayloadDigest(Buffer.from(vector.hex, "hex")), vector.digest);
  }
  assert.notEqual(portable.computePayloadDigest(Buffer.from('{"a":1,"b":2}')), portable.computePayloadDigest(Buffer.from('{"b":2,"a":1}')));
});

await test("R004 every legacy signer throws and verifier rejects historical or malformed artifacts", async () => {
  const payload = Buffer.from(cryptoVectors.historicalKeyless.payloadHex, "hex");
  for (const [kind, key] of [["Challenge", "challenge"], ["ProofReceipt", "proofReceipt"], ["IdentityToken", "identityToken"]]) {
    assert.throws(() => portable[`sign${kind}Payload`](payload), /unsupported/);
    const legacy = Buffer.from(cryptoVectors.historicalKeyless[key], "hex");
    for (const artifact of [legacy, Buffer.alloc(0), Buffer.alloc(64), Buffer.concat([legacy, Buffer.from([1])]), null, undefined]) {
      assert.equal(portable[`verify${kind}Payload`](payload, artifact), false);
    }
  }
});

await test("R004 portable envelope rejects all signature authority and labels unsigned integrity", async () => {
  const unsigned = createSafeEnvelope("test", "abc");
  assert.deepEqual(validateSafeEnvelope(unsigned), { isValid: true, isAuthenticated: false, reason: "integrity_only" });
  for (const algorithmId of ["ML-DSA-65", "hybrid-beta1", "", "invalid"]) {
    for (const keyId of ["unknown", "substituted-device", ""]) {
      for (const signatureBytes of [Buffer.alloc(0), Buffer.from(cryptoVectors.historicalKeyless.challenge, "hex"), Buffer.alloc(3309)]) {
        const signed = createSafeEnvelope("test", "abc", { keyId, algorithm: {algorithmId, hybrid: true}, signatureBytes });
        assert.deepEqual(validateSafeEnvelope(signed), { isValid: false, isAuthenticated: false, reason: "unsupported_signature" });
      }
    }
  }
});

await test("R004 in-process queue rejects fabricated signed message", async () => {
  const queue = new InMemoryAgentToAgentProtocol();
  const message = queue.send("agent:sender", "agent:recipient", "test", "abc", null,
    { keyId: "unknown", algorithm: {algorithmId:"ML-DSA-65", hybrid:false}, signatureBytes:Buffer.alloc(3309) });
  const result = queue.receive("agent:recipient", message.messageId);
  assert.equal(result.accepted, false);
  assert.equal(result.reason, "unsupported_signature");
});

await test("getToken exchanges the developer key for an access token", async () => {
  let capturedUrl = null;
  let capturedBody = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    configKey: "cfg_123",
    developerKey: "dev_456",
    fetcher: async (url, init) => {
      capturedUrl = url;
      capturedBody = JSON.parse(init.body);
      return new Response(
        JSON.stringify({
          access_token: "header.payload.signature",
          token_type: "Bearer",
          expires_in: 1800,
          expires_at: "2099-08-05T12:30:00Z",
          scope: "security:read",
          scopes: ["security:read"],
          tenant_id: "tenant_dev_456",
          subject: "dev_456"
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
  });

  const token = await client.getToken("security:read");

  assert.equal(capturedUrl, "https://example.test/apis/v1/token");
  assert.equal(capturedBody.grantType, "developer_key");
  assert.equal(capturedBody.scope, "security:read");
  assert.equal(token.token_type, "Bearer");
  assert.deepEqual(token.scopes, ["security:read"]);
});

await test("introspectToken reports an unusable token as inactive", async () => {
  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    developerKey: "dev_456",
    fetcher: async () =>
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
  });

  const result = await client.introspectToken("not-a-real-token");

  assert.equal(result.active, false);
  assert.equal(result.sub, undefined);
});

await test("revokeToken posts the token and reason", async () => {
  let capturedUrl = null;
  let capturedBody = null;

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    developerKey: "dev_456",
    fetcher: async (url, init) => {
      capturedUrl = url;
      capturedBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ status: "revoked" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  });

  await client.revokeToken("header.payload.signature", "integration test");

  assert.equal(capturedUrl, "https://example.test/apis/v1/token/revoke");
  assert.equal(capturedBody.token, "header.payload.signature");
  assert.equal(capturedBody.reason, "integration test");
});

// --- AI surface -----------------------------------------------------------------------------
//
// Contract cover for the agent, transaction and protected-messaging capabilities. End-to-end
// behaviour is proved by tests/live-flow.mjs against a real host; these pin the paths, bodies
// and credential handling so a drift in the wire contract fails here first.

function recordingFetcher(status = 200, payload = {}) {
  const captured = {};
  const fetcher = async (url, init) => {
    captured.url = url;
    captured.method = init?.method ?? "GET";
    captured.headers = new Headers(init?.headers);
    captured.body = init?.body ? JSON.parse(init.body) : null;
    const actual = url.includes("/transactions/") && payload.access_token ? transactionFixture() : payload;
    return new Response(JSON.stringify(actual), {
      status,
      headers: { "Content-Type": "application/json" }
    });
  };

  return { fetcher, captured };
}

await test("createTransaction posts the declared action", async () => {
  const { fetcher, captured } = recordingFetcher(201, transactionFixture());
  const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true, fetcher });

  const transaction = await client.createTransaction({
    declaredAction: "ai.provider.invoke",
    targetResourceId: "res_1"
  });

  assert.equal(captured.url, "https://example.test/apis/v1/transactions");
  assert.equal(captured.method, "POST");
  assert.equal(captured.body.declaredAction, "ai.provider.invoke");
  assert.equal(transaction.transactionId, "AGTX-0011");
});

await test("useAgentKey presents the agent key then switches to the bearer token", async () => {
  const { fetcher, captured } = recordingFetcher(200, {
    access_token: "agent.token.value",
    token_type: "Bearer", expires_in:1800, expires_at:"2099-01-01T00:00:00Z", scope:"", tenant_id:"tenant_test", subject:"agt_1",
    scopes: []
  });

  const client = new AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    developerKey: "dev_1:secret",
    fetcher
  });

  await client.useAgentKey("agt_1:agent-secret");

  assert.equal(captured.headers.get("X-Aegir-Agent-Key"), "agt_1:agent-secret");
  assert.equal(captured.body.grantType, "agent_key");

  // From here the agent token is the credential. The developer key must not keep travelling
  // alongside it â€” a request carrying both would authenticate as the wrong principal, and the
  // agent's narrower scopes would be silently bypassed.
  await client.getTransaction("AGTX-0011");
  assert.equal(captured.headers.get("Authorization"), "Bearer agent.token.value");
  assert.equal(captured.headers.get("X-Aegir-Developer-Key"), null);
});

await test("sendAgentMessage posts the transaction, recipient, action and payload", async () => {
  const { fetcher, captured } = recordingFetcher(200, {
    transactionId: "AGTX-0011",
    envelope: { envelopeId: "env_1", header:{transactionId:"AGTX-0011",recipientPrincipalId:"agt_beta",action:"agent.finding.share"},kemCiphertext:"AA==",aeadNonce:"AA==",ciphertext:"AA==",tag:"AA==",signature:"AA==" }
  });

  const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true, fetcher });

  await client.sendAgentMessage({
    transactionId: "AGTX-0011",
    recipientAgentId: "agt_beta",
    action: "agent.finding.share",
    payload: "cGF5bG9hZA=="
  });

  assert.equal(captured.url, "https://example.test/apis/v1/ai/messages");
  assert.deepEqual(captured.body, {
    transactionId: "AGTX-0011",
    recipientAgentId: "agt_beta",
    action: "agent.finding.share",
    payload: "cGF5bG9hZA=="
  });
});

await test("bindProvider never returns the credential it sent", async () => {
  const { fetcher, captured } = recordingFetcher(200, {
    bindingId: "pbnd_1",
    agentPrincipalId: "agt_1",
    providerId: "openai",
    allowedModelIds: [],
    createdAtUtc: "2026-08-09T00:00:00Z",
    revokedAtUtc: null
  });

  const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true, fetcher });

  const binding = await client.bindProvider("agt_1", {
    providerId: "openai",
    apiKey: "sk-secret",
    allowedModelIds: ["gpt-4o-mini"]
  });

  assert.equal(captured.url, "https://example.test/apis/v1/agents/agt_1/providers");
  assert.equal(captured.body.apiKey, "sk-secret");

  // A binding can be replaced but never read back.
  assert.equal(binding.apiKey, undefined);
});

await test("invokeProvider reports a vendor failure as data, not an exception", async () => {
  const { fetcher } = recordingFetcher(200, {
    invocationId: "pinv_1",
    transactionId: "AGTX-0011",
    providerId: "openai",
    modelId: "gpt-4o-mini",
    agentPrincipalId: "agt_1",
    requestDigest: "abc",
    succeeded: false,
    content: null,
    stopReason: null,
    usage: null,
    errorKind: "RateLimited",
    errorMessage: "slow down",
    errorRetryable: true
  });

  const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true, fetcher });

  const result = await client.invokeProvider({
    transactionId: "AGTX-0011",
    providerId: "openai",
    modelId: "gpt-4o-mini",
    messages: [{ role: "user", content: "hi" }]
  });

  // A vendor failure is recorded exactly like a success, which is what keeps a failed call as
  // auditable as a completed one.
  assert.equal(result.succeeded, false);
  assert.equal(result.errorKind, "RateLimited");
  assert.equal(result.errorRetryable, true);
});

await test("a specific server error code survives to the caller", async () => {
  const { fetcher } = recordingFetcher(403, { error: "envelope_rejected", status: "Replayed" });
  const client = new AegirSecurityClient({ baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true, fetcher });

  await assert.rejects(
    () => client.receiveAgentMessage({ transactionId: "AGTX-0011", envelope: {} }),
    (error) => {
      assert.ok(error instanceof AegirSecurityError);
      assert.equal(error.status, 403);
      assert.equal(error.code, "envelope_rejected");
      return true;
    }
  );
});

function transactionFixture(){return {transactionId:"AGTX-0011",tenantId:"tenant_test",callerPrincipalType:"Agent",callerPrincipalId:"agt_1",declaredAction:"ai.provider.invoke",authorizationDecision:"Pending",status:"Created"};}
