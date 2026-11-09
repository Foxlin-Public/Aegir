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
export function createClient(environment = process.env) {
  const baseUrl = environment.AEGIR_BASE_URL;
  if (!baseUrl) {
    throw new Error("AEGIR_BASE_URL is required.");
  }

  if (!environment.AEGIR_DEVELOPER_KEY) {
    throw new Error("AEGIR_DEVELOPER_KEY is required.");
  }

  // AEGIR_CONFIG_KEY is deliberately not read. The API no longer accepts it as a credential
  // on any identity-bearing route, and it still opens the pre-authentication federation and
  // handoff routes — so placing it in a client process is exposure with no benefit.
  return new AegirSecurityClient({
    baseUrl,
    timeoutMs: 30000,
    developerKey: environment.AEGIR_DEVELOPER_KEY,
    ...(environment.AEGIR_MCP_CERTIFICATE_SHA256 ? {certificateSha256:environment.AEGIR_MCP_CERTIFICATE_SHA256} : {})
  });
}

/**
 * Exchanges the developer key for a scope-narrowed access token.
 *
 * Failure is terminal for narrowed execution. Deliberate developer-key execution is selected
 * separately by the process host; this helper never authorizes an ambient-key fallback.
 */
export async function narrowCredentials(client) {
  await client.useNarrowedToken(REQUIRED_SCOPES);
  return true;
}

/** Capture local operator intent once. This authenticates an integration, never a Human delegate. */
export async function prepareExecutionClient(environment = process.env) {
  const snapshot = Object.freeze({
    AEGIR_BASE_URL: environment.AEGIR_BASE_URL,
    AEGIR_DEVELOPER_KEY: environment.AEGIR_DEVELOPER_KEY,
    AEGIR_MCP_CERTIFICATE_SHA256: environment.AEGIR_MCP_CERTIFICATE_SHA256,
    mode: environment.AEGIR_MCP_CREDENTIAL_MODE ?? "narrowed",
    developer: environment.AEGIR_MCP_EXPECTED_DEVELOPER_ID
  });
  if (!["narrowed", "developer-key"].includes(snapshot.mode))
    throw new Error("Unsupported MCP credential mode; Human delegation is unavailable.");
  if (typeof snapshot.developer !== "string" || !/^[A-Za-z0-9_.:-]{1,256}$/.test(snapshot.developer))
    throw new Error("An explicit expected developer identity is required.");
  const bootstrap = createClient(snapshot);
  let issued;
  try {
    issued = await bootstrap.getToken(REQUIRED_SCOPES);
    if (issued.subject !== snapshot.developer || typeof issued.tenant_id !== "string" || issued.tenant_id.length < 1 ||
        !Array.isArray(issued.scopes) || issued.scopes.length !== REQUIRED_SCOPES.split(" ").length ||
        new Set(issued.scopes).size !== issued.scopes.length ||
        issued.scopes.some(s => !REQUIRED_SCOPES.split(" ").includes(s)) ||
        !Number.isFinite(Date.parse(issued.expires_at)) || Date.parse(issued.expires_at) <= Date.now()) throw new Error("MCP authority could not be established.");
  } finally { bootstrap.close(); }
  // The narrowed execution client never receives the ambient developer credential.
  const client = new AegirSecurityClient({ baseUrl: snapshot.AEGIR_BASE_URL,
    timeoutMs: 30000,
    ...(snapshot.AEGIR_MCP_CERTIFICATE_SHA256 ? {certificateSha256:snapshot.AEGIR_MCP_CERTIFICATE_SHA256} : {}),
    ...(snapshot.mode === "narrowed" ? { accessToken: issued.access_token } : { developerKey: snapshot.AEGIR_DEVELOPER_KEY }) });
  async function requireCurrent() {
    const current = await client.introspectToken(issued.access_token);
    if (current.active !== true || current.dev !== snapshot.developer || current.tenant_id !== issued.tenant_id ||
        (current.app ?? "") !== "" || (current.env ?? "") !== "" || (current.roles?.length ?? 0) !== 0 ||
        !Array.isArray(current.scopes) || current.scopes.length !== issued.scopes.length ||
        new Set(current.scopes).size !== current.scopes.length ||
        current.scopes.some(s => !issued.scopes.includes(s))) throw new Error("Current MCP authority is unavailable.");
  }
  try { await requireCurrent(); }
  catch { client.close(); throw new Error("Current MCP authority is unavailable."); }
  // Retained solely to reject reflected credential material, never supplied to a
  // narrowed execution client or used to retry authentication with broader authority.
  const sensitive = [snapshot.AEGIR_DEVELOPER_KEY, snapshot.AEGIR_DEVELOPER_KEY?.split(":").slice(1).join(":"), issued.access_token]
    .filter(value => typeof value === "string" && value.length > 0);
  function assertSafeOutput(value, depth = 0) {
    if (depth > 20) throw new Error("Unsafe output.");
    if (typeof value === "string") {
      if (sensitive.some(secret => value.includes(secret))) throw new Error("Unsafe output.");
      // SDK tools place JSON in content.text; inspect decoded values as well as
      // their escaped representation so Unicode escapes cannot hide a credential.
      if (/^\s*[\[{\"]/.test(value)) {
        let decoded; try { decoded = JSON.parse(value); } catch { return; }
        assertSafeOutput(decoded, depth + 1);
      }
    } else if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) { assertSafeOutput(key, depth + 1); assertSafeOutput(child, depth + 1); }
    }
  }
  return Object.freeze({ client, requireCurrent, assertSafeOutput, mode: snapshot.mode, developer: snapshot.developer });
}

export async function handleMessage(client, message) {
  switch (message.method) {
    case "initialize":
      return {
        protocolVersion: "2025-03-26",
        serverInfo: { name: "aegir-sdk-mcp", version: "0.1.2-beta.1" },
        capabilities: { tools: {} }
      };
    case "tools/list":
      return { tools: TOOLS.map((entry) => tool(entry.name, entry.description, entry.inputShape)) };
    case "tools/call":
      return await handleToolCall(client, message.params ?? {});
    case "ping": return {};
    default:
      throw Object.assign(new Error("Unsupported method."),{code:-32601});
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
  const code = [-32700,-32600,-32601,-32602,-32603,-32800].includes(error?.code) ? error.code : -32000;
  const safeCodes = new Set(["cross_tenant_denied","insufficient_scope","unauthorized","forbidden","authority_continuity_unavailable","security_history_capacity_required"]);
  const semanticCode=typeof error?.code==="string"?error.code:error?.errorCode;
  const errorCode = safeCodes.has(semanticCode) ? semanticCode : null;

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
          key === "receipt" ? receiptSchema() : { type: value.startsWith("string") ? "string" : "object", ...(value.startsWith("string") ? {maxLength:argumentLimit(name,key),minLength:value.endsWith("?")?0:1} : {}), ...(key==="actionType"?{enum:ACTION_TYPES}:{}), ...(name==="open_transaction"&&key==="declaredAction"?{pattern:"^[^\\r\\n\\u0000]+$"}:{}) }
        ])
      ),
      required: Object.entries(inputShape).filter(([,value]) => !value.endsWith("?")).map(([key]) => key),
      additionalProperties: false
    }
  };
}
const ACTION_TYPES=["LockIdentity","DisconnectService","VerifyConnection","RequestClarity"];
function argumentLimit(name,key){return name==="open_transaction"&&key==="declaredAction"?512:4096;}

function receiptSchema() {
  const required = ["transactionId","tenantId","callerPrincipalType","callerPrincipalId","declaredAction","authorizationDecision","status","eventChainRoot","createdAtUtc","issuedAtUtc","signingKid","algorithm","signature"];
  const optional = ["subjectPrincipalId","agentPrincipalId","targetResourceId","policyId","executionOutcome","requestEvidenceHash","responseEvidenceHash","envelopeId","senderKid","recipientKid","completedAtUtc"];
  return {type:"object",properties:Object.fromEntries([...required,...optional].map(key=>[key,{type:optional.includes(key)?["string","null"]:"string",maxLength:32768,...(key.endsWith("AtUtc")?{format:"date-time"}:{})}])),required,additionalProperties:false};
}

async function handleToolCall(client, params) {
  const name = params.name;
  const args = params.arguments ?? {};
  const definition = TOOLS.find(t => t.name === name);
  const invalid = () => Object.assign(new Error("Invalid tool parameters."),{code:-32602});
  if (!definition || typeof params !== "object" || params === null || Array.isArray(params) ||
      Object.keys(params).some(k => !["name","arguments"].includes(k)) || typeof args !== "object" || args === null || Array.isArray(args)) throw invalid();
  if (Object.keys(args).some(k => !Object.hasOwn(definition.inputShape,k))) throw invalid();
  for (const [key,shape] of Object.entries(definition.inputShape)) {
    if (!(key in args)) { if (!shape.endsWith("?")) throw invalid(); continue; }
    if (shape.startsWith("string") ? typeof args[key] !== "string" || args[key].length > argumentLimit(name,key) ||
        (!shape.endsWith("?") && args[key].length < 1) : typeof args[key] !== "object" || args[key] === null || Array.isArray(args[key])) throw invalid();
  }
  if(name==="perform_action"&&!ACTION_TYPES.includes(args.actionType))throw invalid();
  if(name==="open_transaction"&&/[\r\n\0]/.test(args.declaredAction))throw invalid();
  if (name === "verify_transaction_receipt") {
    const schema=receiptSchema(), receipt=args.receipt;
    if (Object.keys(receipt).some(key=>!Object.hasOwn(schema.properties,key)) || schema.required.some(key=>!Object.hasOwn(receipt,key))) throw invalid();
    for (const [key,value] of Object.entries(receipt)) {
      const rule=schema.properties[key];
      if (value===null && Array.isArray(rule.type)) continue;
      if (typeof value!=="string" || value.length>rule.maxLength || (rule.format==="date-time" && !Number.isFinite(Date.parse(value)))) throw invalid();
    }
  }
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
