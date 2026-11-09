import { AegirSecurityClient } from "@foxlin_industries/aegir-security";

const now = "2026-04-07T15:00:00Z";

const sampleGraph = {
  graphId: "graph:developer:dev_123",
  generatedAtUtc: now,
  scores: {
    exposureScore: 0.15,
    trustScore: 0.92,
    connectionClarityScore: 0.88
  },
  nodes: [
    {
      nodeId: "developer:dev_123",
      nodeType: "User",
      displayName: "dev_123@example.com",
      status: "active",
      trustTier: "high",
      observedAtUtc: now,
      lastVerifiedAtUtc: now,
      metadata: {}
    }
  ],
  edges: [],
  metadata: {}
};

const sampleExposure = {
  graphId: sampleGraph.graphId,
  generatedAtUtc: now,
  exposureScore: 0.15,
  findings: [],
  summaryText: "Low exposure posture."
};

const sampleAction = {
  actionId: "action_001",
  subjectId: "developer:dev_123",
  actionType: "VerifyConnection",
  status: "Completed",
  targetNodeId: "application:app_portal",
  reason: "NPM sample validation.",
  requestedAtUtc: now,
  reversedAtUtc: null,
  reverseReason: null,
  metadata: {}
};

const fetcher = async (url, init = {}) => {
  if (url.endsWith("/v1/security/scan/developer%3Adev_123")) {
    return jsonResponse({
      subjectId: "developer:dev_123",
      graph: sampleGraph,
      exposure: sampleExposure,
      actionHistory: [sampleAction]
    });
  }

  if (url.endsWith("/v1/security/graphs/developer%3Adev_123")) {
    return jsonResponse(sampleGraph);
  }

  if (url.endsWith("/v1/security/exposure/developer%3Adev_123")) {
    return jsonResponse(sampleExposure);
  }

  if (url.endsWith("/v1/security/actions") && init.method === "POST") {
    return jsonResponse(sampleAction);
  }

  return new Response(JSON.stringify({ error: "not_found" }), {
    status: 404,
    headers: { "Content-Type": "application/json" }
  });
};

const client = new AegirSecurityClient({
  baseUrl: "https://api.aegir.foxlinindustries.com/apis",
  developerKey: "sample-developer-key",
  fetcher
});

const scan = await client.scanIdentity("developer:dev_123");
const graphJson = await client.getIdentityGraphJson("developer:dev_123");
const exposure = await client.getExposureSummary("developer:dev_123");
const action = await client.performAction({
  subjectId: "developer:dev_123",
  actionType: "VerifyConnection",
  targetNodeId: "application:app_portal",
  reason: "NPM sample validation."
});

console.log("NPM sample executed successfully.");
console.log(`scanIdentity subject: ${scan.subjectId}`);
console.log(`graph id: ${scan.graph.graphId}`);
console.log(`exposure summary: ${exposure.summaryText}`);
console.log(`action result: ${action.actionType} -> ${action.status}`);
console.log(`serialized graph contains graphId: ${graphJson.includes("graph:developer:dev_123")}`);

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}
