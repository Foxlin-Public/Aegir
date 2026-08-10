import assert from "node:assert/strict";
import { handleMessage } from "../src/server.mjs";

const calls = [];
const client = {
  async scanIdentity(subjectId) {
    calls.push(["scanIdentity", subjectId]);
    return { subjectId };
  },
  async getIdentityGraph(subjectId) {
    calls.push(["getIdentityGraph", subjectId]);
    return { graphId: `graph:${subjectId}` };
  },
  async getIdentityGraphJson(subjectId) {
    calls.push(["getIdentityGraphJson", subjectId]);
    return JSON.stringify({ graphId: `graph:${subjectId}` });
  },
  async getExposureSummary(subjectId) {
    calls.push(["getExposureSummary", subjectId]);
    return { graphId: `graph:${subjectId}` };
  },
  async performAction(request) {
    calls.push(["performAction", request.subjectId]);
    return { actionId: "action_001", subjectId: request.subjectId };
  },
  async reverseAction(actionId, reason) {
    calls.push(["reverseAction", actionId, reason]);
    return { actionId, reason };
  },
  async getActionHistory(subjectId) {
    calls.push(["getActionHistory", subjectId]);
    return [{ subjectId }];
  },
  async createTransaction(request) {
    calls.push(["createTransaction", request.declaredAction]);
    return { transactionId: "AGTX-0011", status: "Created" };
  },
  async getTransaction(transactionId) {
    calls.push(["getTransaction", transactionId]);
    return { transactionId, status: "Completed" };
  },
  async getTransactionEvents(transactionId) {
    calls.push(["getTransactionEvents", transactionId]);
    return [{ sequence: 1, eventType: "transaction.created" }];
  },
  async getTransactionReceipt(transactionId) {
    calls.push(["getTransactionReceipt", transactionId]);
    return { transactionId, algorithm: "ML-DSA-65", signature: "c2ln" };
  },
  async verifyTransactionReceipt(receipt) {
    calls.push(["verifyTransactionReceipt", receipt.transactionId]);
    return { valid: true, status: "Valid", detail: null };
  }
};

const init = await handleMessage(client, { method: "initialize" });
assert.equal(init.serverInfo.name, "aegir-sdk-mcp");

const listed = await handleMessage(client, { method: "tools/list" });
assert.equal(Array.isArray(listed.tools), true);
assert.equal(listed.tools.some((tool) => tool.name === "scan_identity"), true);

const scanned = await handleMessage(client, {
  method: "tools/call",
  params: { name: "scan_identity", arguments: { subjectId: "developer:dev_123" } }
});
assert.equal(scanned.content[0].text.includes("developer:dev_123"), true);

const reversed = await handleMessage(client, {
  method: "tools/call",
  params: { name: "reverse_action", arguments: { actionId: "action_001", reason: "test" } }
});
assert.equal(reversed.content[0].text.includes("action_001"), true);

assert.deepEqual(calls[0], ["scanIdentity", "developer:dev_123"]);


// --- Security regression coverage for the Beta-1 Node MCP audit -------------------------

import { createClient, createJsonRpcError, narrowCredentials, REQUIRED_SCOPES } from "../src/core.mjs";

// The config key is deliberately not read into this process: the API no longer accepts it
// as a credential, and it still opens the pre-authentication federation and handoff routes.
{
  const previous = {
    baseUrl: process.env.AEGIR_BASE_URL,
    configKey: process.env.AEGIR_CONFIG_KEY,
    developerKey: process.env.AEGIR_DEVELOPER_KEY
  };

  process.env.AEGIR_BASE_URL = "https://aegir.test/apis";
  process.env.AEGIR_CONFIG_KEY = "cfg_should_not_be_used";
  process.env.AEGIR_DEVELOPER_KEY = "devkey_active:secret";

  const client = createClient();
  const captured = [];
  client.getToken = async () => {
    throw new Error("token endpoint unavailable");
  };

  assert.equal(await narrowCredentials(client), false, "narrowing must not throw when unsupported");

  // Prove no config-key header is sent, by driving one real request through a stub fetcher.
  const probe = createClient();
  probe.fetcher = undefined;
  const inspected = new (Object.getPrototypeOf(probe).constructor)({
    baseUrl: "https://aegir.test/apis",
    developerKey: "devkey_active:secret",
    fetcher: async (_url, init) => {
      captured.push(new Headers(init?.headers));
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }
  });

  await inspected.scanIdentity("user_1");
  assert.equal(captured[0].get("X-Aegir-Config-Key"), null, "config key must not be sent");
  assert.equal(captured[0].get("X-Aegir-Developer-Key"), "devkey_active:secret");

  process.env.AEGIR_BASE_URL = previous.baseUrl;
  process.env.AEGIR_CONFIG_KEY = previous.configKey;
  process.env.AEGIR_DEVELOPER_KEY = previous.developerKey;
}

// A narrowed token replaces the developer key on the wire.
{
  const captured = [];
  const { AegirSecurityClient } = await import("../../packages/npm/dist/esm/index.js");
  const client = new AegirSecurityClient({
    baseUrl: "https://aegir.test/apis",
    developerKey: "devkey_active:secret",
    fetcher: async (_url, init) => {
      captured.push(new Headers(init?.headers));
      return new Response(
        JSON.stringify({
          access_token: "h.p.s",
          token_type: "Bearer",
          expires_in: 1800,
          expires_at: "2026-08-05T12:30:00Z",
          scope: REQUIRED_SCOPES,
          scopes: REQUIRED_SCOPES.split(" "),
          tenant_id: "tenant_dev",
          subject: "dev"
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
  });

  await client.useNarrowedToken(REQUIRED_SCOPES);
  await client.scanIdentity("user_1");

  assert.equal(captured[1].get("Authorization"), "Bearer h.p.s");
  assert.equal(captured[1].get("X-Aegir-Developer-Key"), null, "developer key must not persist once a token exists");
}

// Errors do not leak server-supplied detail to the MCP client.
{
  const rendered = createJsonRpcError(7, Object.assign(new Error("subject dev_other belongs to tenant tenant_x"), {
    code: -32000,
    errorCode: "cross_tenant_denied"
  }));

  assert.equal(rendered.error.message, "Aegir rejected the request (cross_tenant_denied).");
  assert.ok(!rendered.error.message.includes("tenant_x"), "server detail must not be forwarded");
}

console.log("ok - node mcp security regressions");


// --- Transaction audit surface ---------------------------------------------------------
//
// The server exposes audit authority and nothing adjacent to it. Reading transaction evidence
// proves what Aegir decided and did; it must not become a route to identity resolution or to
// decrypting protected data, which are separate scopes this server never requests.

const transactionTools = await handleMessage(client, { method: "tools/list" });
for (const name of [
  "open_transaction",
  "get_transaction",
  "get_transaction_events",
  "get_transaction_receipt",
  "verify_transaction_receipt"
]) {
  assert.equal(
    transactionTools.tools.some((tool) => tool.name === name),
    true,
    `${name} is not exposed`
  );
}

const opened = await handleMessage(client, {
  method: "tools/call",
  params: { name: "open_transaction", arguments: { declaredAction: "mcp.smoke" } }
});
assert.equal(opened.content[0].text.includes("AGTX-0011"), true);

const receipt = await handleMessage(client, {
  method: "tools/call",
  params: { name: "get_transaction_receipt", arguments: { transactionId: "AGTX-0011" } }
});
assert.equal(receipt.content[0].text.includes("ML-DSA-65"), true);

const verified = await handleMessage(client, {
  method: "tools/call",
  params: {
    name: "verify_transaction_receipt",
    arguments: { receipt: { transactionId: "AGTX-0011" } }
  }
});
assert.equal(verified.content[0].text.includes('"valid": true'), true);

// The scope request stays minimal. Widening it here would hand every MCP caller more authority
// than any tool on this server needs.
for (const forbidden of ["identity:resolve", "protected:decrypt", "admin:full", "developer:write"]) {
  assert.equal(REQUIRED_SCOPES.includes(forbidden), false, `${forbidden} must not be requested`);
}

console.log("ok - node mcp transaction audit surface");
