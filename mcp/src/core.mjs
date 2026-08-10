import { AegirSecurityClient } from "../../packages/npm/dist/esm/index.js";

/**
 * The scopes this server actually needs.
 *
 * Its tools map to /v1/security/* and to the transaction audit surface, so it asks for those
 * and nothing else — notably not developer:write, admin:full, identity:resolve or
 * protected:decrypt. Transaction authority here is read-and-open: it proves what Aegir decided
 * and did, and confers no ability to resolve a principal to a person or to decrypt anything.
 */
export const REQUIRED_SCOPES =
  "security:read security:write transaction:read transaction:write";

/**
 * Builds the Aegir client this server proxies through.
 *
 * Trust model, stated plainly: this is a **stdio** server. Its transport carries no caller
 * identity, so anything able to talk to the process acts with the authority of the developer
 * key in its environment. That is the normal shape for a locally launched MCP server, but it
 * means the process boundary — not the protocol — is the security boundary. Do not expose it
 * over a network transport without adding per-caller authentication.
 *
 * Authorization itself is never decided here. Every tool call goes to the Aegir API, which
 * enforces scope, tenancy and claim binding server-side. This server deliberately duplicates
 * none of those rules.
 */
export function createClient() {
  const baseUrl = process.env.AEGIR_BASE_URL;
  if (!baseUrl) {
    throw new Error("AEGIR_BASE_URL is required.");
  }

  if (!process.env.AEGIR_DEVELOPER_KEY) {
    throw new Error("AEGIR_DEVELOPER_KEY is required.");
  }

  // AEGIR_CONFIG_KEY is deliberately not read. The API no longer accepts it as a credential
  // on any identity-bearing route, and it still opens the pre-authentication federation and
  // handoff routes — so placing it in a client process is exposure with no benefit.
  return new AegirSecurityClient({
    baseUrl,
    developerKey: process.env.AEGIR_DEVELOPER_KEY
  });
}

/**
 * Exchanges the developer key for a scope-narrowed access token.
 *
 * Best-effort: if the deployment predates the token endpoint the server keeps working on the
 * developer key, which the API still accepts. Least privilege when available, no hard failure
 * when it is not.
 */
export async function narrowCredentials(client) {
  try {
    await client.useNarrowedToken(REQUIRED_SCOPES);
    return true;
  } catch {
    return false;
  }
}

export async function handleMessage(client, message) {
  switch (message.method) {
    case "initialize":
      return {
        protocolVersion: "2025-03-26",
        serverInfo: { name: "aegir-sdk-mcp", version: "0.1.1-beta-1" },
        capabilities: { tools: {} }
      };
    case "tools/list":
      return { tools: TOOLS.map((entry) => tool(entry.name, entry.description, entry.inputShape)) };
    case "tools/call":
      return await handleToolCall(client, message.params ?? {});
    default:
      throw new Error(`Unsupported method '${message.method}'.`);
  }
}

export function createJsonRpcSuccess(id, result) {
  return { jsonrpc: "2.0", id, result };
}

/**
 * Builds a JSON-RPC error.
 *
 * Aegir error codes are forwarded because a caller needs them to react, but server-supplied
 * detail is not: an MCP client is not the right audience for it, and the authoritative record
 * is the Aegir audit trail.
 */
export function createJsonRpcError(id, error) {
  const code = typeof error?.code === "number" ? error.code : -32000;
  const errorCode = typeof error?.errorCode === "string" ? error.errorCode : null;

  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message: errorCode
        ? `Aegir rejected the request (${errorCode}).`
        : "The Aegir request could not be completed."
    }
  };
}

/**
 * The single definition of what this server exposes.
 *
 * `tools/list` and {@link getToolDescriptors} both derive from this. They used to be written
 * out separately, so adding a tool to one silently left the other stale — and `tools/list` is
 * the one clients actually read.
 */
const TOOLS = [
  {
    name: "scan_identity",
    description: "Scan an identity subject.",
    inputShape: { subjectId: "string" }
  },
  {
    name: "get_identity_graph",
    description: "Get an identity graph snapshot.",
    inputShape: { subjectId: "string" }
  },
  {
    name: "get_identity_graph_json",
    description: "Get an identity graph snapshot as JSON.",
    inputShape: { subjectId: "string" }
  },
  {
    name: "get_exposure_summary",
    description: "Get an exposure summary.",
    inputShape: { subjectId: "string" }
  },
  {
    name: "perform_action",
    description: "Perform an identity action.",
    inputShape: {
      subjectId: "string",
      actionType: "string",
      targetNodeId: "string?",
      reason: "string?"
    }
  },
  {
    name: "reverse_action",
    description: "Reverse an identity action.",
    inputShape: { actionId: "string", reason: "string?" }
  },
  {
    name: "get_action_history",
    description: "Get the action history for a subject.",
    inputShape: { subjectId: "string" }
  },
  {
    name: "open_transaction",
    description:
      "Open a canonical Aegir transaction before performing a protected operation, so a denied or abandoned attempt is audited too.",
    inputShape: {
      declaredAction: "string",
      targetResourceId: "string?",
      subjectPrincipalId: "string?",
      externalCorrelationId: "string?"
    }
  },
  {
    name: "get_transaction",
    description: "Read a transaction's status and authorization decision.",
    inputShape: { transactionId: "string" }
  },
  {
    name: "get_transaction_events",
    description: "Read a transaction's hash-chained event history.",
    inputShape: { transactionId: "string" }
  },
  {
    name: "get_transaction_receipt",
    description:
      "Issue an ML-DSA-65 signed receipt for a transaction. Carries verification assertions, never protected data.",
    inputShape: { transactionId: "string" }
  },
  {
    name: "verify_transaction_receipt",
    description: "Verify a previously issued receipt, including whether its key was valid when it signed.",
    inputShape: { receipt: "object" }
  }
];

export function getToolDescriptors() {
  return TOOLS.map(({ name, description }) => ({ name, description }));
}

function tool(name, description, inputShape) {
  return {
    name,
    description,
    inputSchema: {
      type: "object",
      properties: Object.fromEntries(
        Object.entries(inputShape).map(([key, value]) => [
          key,
          { type: value.startsWith("string") ? "string" : "object" }
        ])
      )
    }
  };
}

async function handleToolCall(client, params) {
  const name = params.name;
  const args = params.arguments ?? {};
  let result;

  switch (name) {
    case "scan_identity":
      result = await client.scanIdentity(args.subjectId);
      break;
    case "get_identity_graph":
      result = await client.getIdentityGraph(args.subjectId);
      break;
    case "get_identity_graph_json":
      result = await client.getIdentityGraphJson(args.subjectId);
      break;
    case "get_exposure_summary":
      result = await client.getExposureSummary(args.subjectId);
      break;
    case "perform_action":
      result = await client.performAction(args);
      break;
    case "reverse_action":
      result = await client.reverseAction(args.actionId, args.reason);
      break;
    case "get_action_history":
      result = await client.getActionHistory(args.subjectId);
      break;
    case "open_transaction":
      result = await client.createTransaction({
        declaredAction: args.declaredAction,
        targetResourceId: args.targetResourceId,
        subjectPrincipalId: args.subjectPrincipalId,
        externalCorrelationId: args.externalCorrelationId
      });
      break;
    case "get_transaction":
      result = await client.getTransaction(args.transactionId);
      break;
    case "get_transaction_events":
      result = await client.getTransactionEvents(args.transactionId);
      break;
    case "get_transaction_receipt":
      result = await client.getTransactionReceipt(args.transactionId);
      break;
    case "verify_transaction_receipt":
      result = await client.verifyTransactionReceipt(args.receipt);
      break;
    default:
      throw new Error(`Unsupported tool '${name}'.`);
  }

  return {
    content: [
      {
        type: "text",
        text: typeof result === "string" ? result : JSON.stringify(result, null, 2)
      }
    ]
  };
}
