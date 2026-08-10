import { createHash } from "crypto";

export interface IdentityGraphScores {
  exposureScore: number;
  trustScore: number;
  connectionClarityScore: number;
}

export type IdentityGraphNodeType =
  | "Platform"
  | "Developer"
  | "DeveloperKey"
  | "Application"
  | "Environment"
  | "User"
  | "Device"
  | "Credential"
  | "Challenge"
  | "Token"
  | "AuditAnchor"
  | "PolicyScope"
  | "ExternalService";

export type IdentityGraphEdgeType =
  | "Owns"
  | "Issued"
  | "Registered"
  | "BelongsTo"
  | "AuthorizedFor"
  | "ScopedTo"
  | "Uses"
  | "PresentedBy"
  | "DerivedFrom"
  | "ApprovedBy"
  | "RevokedBy"
  | "AnchoredBy"
  | "ConnectedTo"
  | "ObservedOn";

export type ExposureFindingCategory =
  | "WeakConnection"
  | "UnknownConnection"
  | "StaleCredential"
  | "HighRiskLinkage";

export type ExposureFindingSeverity =
  | "Low"
  | "Medium"
  | "High";

export interface IdentityGraphNode {
  nodeId: string;
  nodeType: IdentityGraphNodeType;
  displayName: string;
  status: string;
  trustTier: string;
  observedAtUtc: string;
  lastVerifiedAtUtc: string | null;
  metadata: Record<string, string | null>;
}

export interface IdentityGraphEdge {
  edgeId: string;
  edgeType: IdentityGraphEdgeType;
  fromNodeId: string;
  toNodeId: string;
  status: string;
  trustWeight: number;
  evidenceType: string;
  reason: string;
  observedAtUtc: string;
  lastVerifiedAtUtc: string | null;
  metadata: Record<string, string | null>;
}

export interface IdentityGraphSnapshot {
  graphId: string;
  generatedAtUtc: string;
  scores: IdentityGraphScores;
  nodes: IdentityGraphNode[];
  edges: IdentityGraphEdge[];
  metadata: Record<string, string | null>;
}

export interface ExposureFinding {
  findingId: string;
  category: ExposureFindingCategory;
  severity: ExposureFindingSeverity;
  summary: string;
  nodeId: string | null;
  edgeId: string | null;
  metadata: Record<string, string | null>;
}

export interface ExposureSummary {
  graphId: string;
  generatedAtUtc: string;
  exposureScore: number;
  findings: ExposureFinding[];
  summaryText: string;
}

export type IdentityActionType =
  | "LockIdentity"
  | "DisconnectService"
  | "VerifyConnection"
  | "RequestClarity";

export type IdentityActionStatus =
  | "Completed"
  | "Reversed";

export interface PerformIdentityActionRequest {
  subjectId: string;
  actionType: IdentityActionType;
  targetNodeId?: string;
  reason?: string;
}

export interface IdentityActionRecord {
  actionId: string;
  subjectId: string;
  actionType: IdentityActionType;
  status: IdentityActionStatus;
  targetNodeId: string | null;
  reason: string | null;
  requestedAtUtc: string;
  reversedAtUtc: string | null;
  reverseReason: string | null;
  metadata: Record<string, string | null>;
}

export interface ScanIdentityResult {
  subjectId: string;
  graph: IdentityGraphSnapshot;
  exposure: ExposureSummary;
  actionHistory: IdentityActionRecord[];
}

/** A token issued by POST /v1/token. */
export interface AegirAccessToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at: string;
  scope: string;
  scopes: string[];
  tenant_id: string;
  subject: string;
}

/** The response shape of POST /v1/introspect. */
export interface AegirIntrospection {
  active: boolean;
  sub?: string;
  dev?: string;
  app?: string;
  env?: string;
  tenant_id?: string;
  scopes?: string[];
  roles?: string[];
  exp?: number;
}

export interface AegirSecurityClientOptions {
  baseUrl: string;
  configKey?: string;
  developerKey?: string;
  /**
   * A signed Aegir access token. Preferred over `developerKey` for ongoing calls: a token
   * carries only the scopes it was narrowed to and expires, whereas a developer key is a
   * long-lived credential with the full developer scope set.
   */
  accessToken?: string;
  fetcher?: typeof fetch;
  diagnosticsHooks?: AegirDiagnosticsHooks;
}

export type AegirErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "budget_exhausted"
  | "server_error"
  | "transport_error"
  | "unknown_error";

export type AegirLogLevel = "debug" | "information" | "warning" | "error";

export interface AegirLogEntry {
  level: AegirLogLevel;
  eventName: string;
  message: string;
  operation: string;
  correlationId: string | null;
  occurredAtUtc: string;
  metadata: Record<string, string | null>;
}

export interface AegirMetricEvent {
  metricName: string;
  value: number;
  unit: string;
  observedAtUtc: string;
  dimensions: Record<string, string | null>;
}

export interface AegirTraceEvent {
  traceName: string;
  operation: string;
  tracePhase: string;
  occurredAtUtc: string;
  correlationId: string | null;
  metadata: Record<string, string | null>;
}

export interface AegirDiagnosticsHooks {
  log?: (entry: AegirLogEntry) => void | Promise<void>;
  metric?: (event: AegirMetricEvent) => void | Promise<void>;
  trace?: (event: AegirTraceEvent) => void | Promise<void>;
}

export interface TrustCoreAlgorithmDescriptor {
  algorithmId: string;
  hybrid: boolean;
}

export interface TrustCoreSignatureEnvelope {
  keyId: string;
  algorithm: TrustCoreAlgorithmDescriptor;
  signatureBytes: Uint8Array;
}

export interface SafeEnvelopeRecord {
  envelopeId: string;
  payloadType: string;
  canonicalPayload: string;
  payloadHash: string;
  createdAtUtc: string;
  signatureEnvelope: TrustCoreSignatureEnvelope | null;
}

export interface SafeEnvelopeValidationResult {
  isValid: boolean;
  reason: string;
}

export type OperationalControlType =
  | "IdentityScan"
  | "ExternalLookup"
  | "ConnectionGraphRebuild";

export interface BudgetEnvelope {
  controlType: OperationalControlType;
  subjectKey: string;
  windowStartedAtUtc: string;
  windowEndsAtUtc: string;
  limit: number;
  consumed: number;
  remaining: number;
  isExhausted: boolean;
}

export interface BudgetEnvelopeOptions {
  identityScanLimit?: number;
  externalLookupLimit?: number;
  connectionGraphRebuildLimit?: number;
  windowMs?: number;
}

export interface AgentToAgentMessageRecord {
  messageId: string;
  senderAgentId: string;
  recipientAgentId: string;
  messageType: string;
  correlationId: string;
  envelope: SafeEnvelopeRecord;
  sentAtUtc: string;
  receivedAtUtc: string | null;
}

export interface AgentToAgentReceiveResult {
  accepted: boolean;
  reason: string;
  message: AgentToAgentMessageRecord | null;
}

export function signChallengePayload(payload: Uint8Array): Uint8Array {
  return signPayload(payload, 13, 83);
}

export function verifyChallengePayload(payload: Uint8Array, signature: Uint8Array): boolean {
  return verifyPayload(payload, signature, 13, 83);
}

export function signProofReceiptPayload(payload: Uint8Array): Uint8Array {
  return signPayload(payload, 29, 107);
}

export function verifyProofReceiptPayload(payload: Uint8Array, signature: Uint8Array): boolean {
  return verifyPayload(payload, signature, 29, 107);
}

export function signIdentityTokenPayload(payload: Uint8Array): Uint8Array {
  return signPayload(payload, 41, 149);
}

export function verifyIdentityTokenPayload(payload: Uint8Array, signature: Uint8Array): boolean {
  return verifyPayload(payload, signature, 41, 149);
}

export interface AegirTransaction {
  transactionId: string;
  tenantId: string;
  callerPrincipalType: string;
  callerPrincipalId: string;
  subjectPrincipalId: string | null;
  agentPrincipalId: string | null;
  declaredAction: string;
  targetResourceId: string | null;
  policyId: string | null;
  authorizationDecision: string;
  status: string;
  executionOutcome: string | null;
  requestEvidenceHash: string | null;
  responseEvidenceHash: string | null;
  envelopeId: string | null;
  externalCorrelationId: string | null;
  createdAtUtc: string;
  updatedAtUtc: string;
  expiresAtUtc: string | null;
  completedAtUtc: string | null;
}

export interface AegirTransactionEvent {
  sequence: number;
  eventType: string;
  status: string;
  occurredAtUtc: string;
  detail: string | null;
  evidenceHash: string | null;
  eventHash: string;
}

/**
 * A signed receipt for a transaction.
 *
 * Carries verification assertions, never the underlying protected data: no prompt, no payload,
 * no personal identity. A holder can prove what Aegir decided without learning who it was
 * about.
 */
export interface AegirTransactionReceipt {
  transactionId: string;
  tenantId: string;
  callerPrincipalType: string;
  callerPrincipalId: string;
  subjectPrincipalId: string | null;
  agentPrincipalId: string | null;
  declaredAction: string;
  targetResourceId: string | null;
  policyId: string | null;
  authorizationDecision: string;
  status: string;
  executionOutcome: string | null;
  requestEvidenceHash: string | null;
  responseEvidenceHash: string | null;
  eventChainRoot: string;
  envelopeId: string | null;
  senderKid: string | null;
  recipientKid: string | null;
  createdAtUtc: string;
  completedAtUtc: string | null;
  issuedAtUtc: string;
  signingKid: string;
  algorithm: string;
  signature: string;
}

export interface AegirReceiptVerification {
  valid: boolean;
  status: string;
  detail: string | null;
}

export interface AegirAgentRecord {
  agentId: string;
  tenantId: string;
  developerAccountId: string;
  applicationId: string | null;
  displayName: string;
  providerId: string | null;
  modelId: string | null;
  status: string;
  scopes: string[];
  createdAtUtc: string;
  expiresAtUtc: string | null;
  revokedAtUtc: string | null;
}

export interface AegirAgentRegistration {
  agent: AegirAgentRecord;
  credentialId: string;
  agentKey: string;
}

export interface AegirProviderBinding {
  bindingId: string;
  agentPrincipalId: string;
  providerId: string;
  allowedModelIds: string[];
  createdAtUtc: string;
  revokedAtUtc: string | null;
}

export interface AegirModelMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface AegirInvokeProviderRequest {
  transactionId: string;
  providerId: string;
  modelId: string;
  messages: AegirModelMessage[];
  maxOutputTokens?: number;
  temperature?: number;
}

export interface AegirInvocationResult {
  invocationId: string;
  transactionId: string;
  providerId: string;
  modelId: string;
  agentPrincipalId: string;
  requestDigest: string;
  succeeded: boolean;
  content: string | null;
  stopReason: string | null;
  usage: { inputTokens: number; outputTokens: number } | null;
  errorKind: string | null;
  errorMessage: string | null;
  errorRetryable: boolean;
}

/**
 * The authenticated cleartext header of a protected envelope.
 *
 * Every field here is covered by the ML-DSA signature, the HKDF context and the AEAD tag.
 * Altering any of them — including `transactionId` — makes the envelope fail validation.
 */
export interface AegirEnvelopeHeader {
  version: string;
  kemAlgorithm: string;
  signatureAlgorithm: string;
  aeadAlgorithm: string;
  transactionId: string;
  externalCorrelationId: string | null;
  senderPrincipalId: string;
  senderKid: string;
  recipientPrincipalId: string;
  recipientKid: string;
  action: string;
  target: string | null;
  nonce: string;
  issuedAtUtc: string;
  expiresAtUtc: string;
}

/** A payload protected to one agent and authenticated to another. Binary fields are base64. */
export interface AegirProtectedEnvelope {
  envelopeId: string;
  header: AegirEnvelopeHeader;
  kemCiphertext: string;
  aeadNonce: string;
  ciphertext: string;
  tag: string;
  signature: string;
}

export interface AegirAgentMessage {
  transactionId: string;
  envelope: AegirProtectedEnvelope;
}

export interface AegirAgentMessageDelivery {
  senderAgentId: string;
  transactionId: string;
  action: string;
  /** Base64 payload. */
  payload: string;
}

export class AegirSecurityError extends Error {
  public readonly status: number;
  public readonly code: AegirErrorCode;
  public readonly correlationId: string | null;
  public readonly body: unknown;

  public constructor(message: string, status: number, code: AegirErrorCode, correlationId: string | null, body: unknown) {
    super(message);
    this.name = "AegirSecurityError";
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
    this.body = body;
  }
}

export class BudgetExhaustedError extends Error {
  public readonly envelope: BudgetEnvelope;

  public constructor(envelope: BudgetEnvelope) {
    super(`Budget exhausted for ${envelope.controlType} on '${envelope.subjectKey}'.`);
    this.name = "BudgetExhaustedError";
    this.envelope = envelope;
  }
}

export function createSafeEnvelope(
  payloadType: string,
  canonicalPayload: string,
  signatureEnvelope?: TrustCoreSignatureEnvelope | null
): SafeEnvelopeRecord {
  if (!payloadType.trim()) {
    throw new Error("A payloadType is required.");
  }

  if (!canonicalPayload.trim()) {
    throw new Error("A canonicalPayload is required.");
  }

  return {
    envelopeId: createRuntimeId("env"),
    payloadType,
    canonicalPayload,
    payloadHash: computePayloadHash(canonicalPayload),
    createdAtUtc: new Date().toISOString(),
    signatureEnvelope: signatureEnvelope ?? null
  };
}

export function validateSafeEnvelope(envelope: SafeEnvelopeRecord): SafeEnvelopeValidationResult {
  if (envelope.payloadHash !== computePayloadHash(envelope.canonicalPayload)) {
    return { isValid: false, reason: "payload_hash_mismatch" };
  }

  if (envelope.signatureEnvelope && envelope.signatureEnvelope.signatureBytes.length === 0) {
    return { isValid: false, reason: "signature_missing" };
  }

  return { isValid: true, reason: "valid" };
}

export class InMemoryBudgetEnvelopeService {
  private readonly windowMs: number;
  private readonly limits: Record<OperationalControlType, number>;
  private readonly counters = new Map<string, { windowStartedAtUtc: number; consumed: number }>();

  public constructor(options: BudgetEnvelopeOptions = {}) {
    this.windowMs = options.windowMs ?? 60_000;
    this.limits = {
      IdentityScan: options.identityScanLimit ?? 25,
      ExternalLookup: options.externalLookupLimit ?? 50,
      ConnectionGraphRebuild: options.connectionGraphRebuildLimit ?? 10
    };
  }

  public getEnvelope(controlType: OperationalControlType, subjectKey: string): BudgetEnvelope {
    const key = buildBudgetKey(controlType, subjectKey);
    const current = this.counters.get(key) ?? { windowStartedAtUtc: Date.now(), consumed: 0 };
    return toBudgetEnvelope(controlType, subjectKey, current, this.windowMs, this.limits[controlType]);
  }

  public consume(controlType: OperationalControlType, subjectKey: string): BudgetEnvelope {
    const key = buildBudgetKey(controlType, subjectKey);
    const now = Date.now();
    const current = this.counters.get(key);
    const resolved =
      current && now - current.windowStartedAtUtc < this.windowMs
        ? { ...current, consumed: current.consumed + 1 }
        : { windowStartedAtUtc: now, consumed: 1 };
    this.counters.set(key, resolved);

    const envelope = toBudgetEnvelope(controlType, subjectKey, resolved, this.windowMs, this.limits[controlType]);
    if (resolved.consumed > envelope.limit) {
      throw new BudgetExhaustedError(envelope);
    }

    return envelope;
  }
}

/**
 * A local, in-process message queue for development and offline tests.
 *
 * @deprecated This is a simulation, not Aegir protection. Its envelopes are not encrypted,
 * its signatures are not cryptographic, and nothing here is bound to an Aegir transaction or
 * checked against an agent identity. For real agent-to-agent protection use
 * {@link AegirSecurityClient.sendAgentMessage} and
 * {@link AegirSecurityClient.receiveAgentMessage}, which go through the server's ML-KEM-768 /
 * AES-256-GCM / ML-DSA-65 envelope.
 */
export class InMemoryAgentToAgentProtocol {
  private readonly inbox = new Map<string, AgentToAgentMessageRecord[]>();

  public send(
    senderAgentId: string,
    recipientAgentId: string,
    messageType: string,
    canonicalPayload: string,
    correlationId?: string | null,
    signatureEnvelope?: TrustCoreSignatureEnvelope | null
  ): AgentToAgentMessageRecord {
    if (!senderAgentId.trim()) {
      throw new Error("A senderAgentId is required.");
    }

    if (!recipientAgentId.trim()) {
      throw new Error("A recipientAgentId is required.");
    }

    if (!messageType.trim()) {
      throw new Error("A messageType is required.");
    }

    const message: AgentToAgentMessageRecord = {
      messageId: createRuntimeId("msg"),
      senderAgentId,
      recipientAgentId,
      messageType,
      correlationId: correlationId?.trim() || createRuntimeId("corr"),
      envelope: createSafeEnvelope(`agent:${messageType}`, canonicalPayload, signatureEnvelope),
      sentAtUtc: new Date().toISOString(),
      receivedAtUtc: null
    };

    const items = this.inbox.get(recipientAgentId) ?? [];
    items.push(message);
    items.sort((left, right) => left.sentAtUtc.localeCompare(right.sentAtUtc));
    this.inbox.set(recipientAgentId, items);
    return message;
  }

  public getInbox(recipientAgentId: string): AgentToAgentMessageRecord[] {
    return [...(this.inbox.get(recipientAgentId) ?? [])];
  }

  public receive(recipientAgentId: string, messageId: string): AgentToAgentReceiveResult {
    const items = this.inbox.get(recipientAgentId) ?? [];
    const index = items.findIndex((candidate) => candidate.messageId === messageId);
    if (index < 0) {
      return { accepted: false, reason: "message_not_found", message: null };
    }

    const message = items[index];
    const validation = validateSafeEnvelope(message.envelope);
    if (!validation.isValid) {
      return { accepted: false, reason: validation.reason, message };
    }

    const accepted = { ...message, receivedAtUtc: new Date().toISOString() };
    items[index] = accepted;
    this.inbox.set(recipientAgentId, items);
    return { accepted: true, reason: "accepted", message: accepted };
  }
}

export class AegirSecurityClient {
  private readonly baseUrl: string;
  private readonly configKey?: string;
  private readonly developerKey?: string;
  private accessToken?: string;
  private readonly fetcher: typeof fetch;
  private readonly diagnosticsHooks?: AegirDiagnosticsHooks;

  public constructor(options: AegirSecurityClientOptions) {
    if (!options?.baseUrl?.trim()) {
      throw new Error("A baseUrl is required.");
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.configKey = options.configKey;
    this.developerKey = options.developerKey;
    this.accessToken = options.accessToken;
    this.fetcher = options.fetcher ?? globalThis.fetch;
    this.diagnosticsHooks = options.diagnosticsHooks;

    if (!this.fetcher) {
      throw new Error("A fetch implementation is required.");
    }
  }

  /**
   * Exchanges the configured developer key for a signed access token.
   *
   * Beta-1 SDKs could call the identity-security operations but had no way to obtain,
   * inspect or revoke a credential. `scope` narrows the grant; it can never widen it.
   */
  public async getToken(scope?: string): Promise<AegirAccessToken> {
    return await this.request<AegirAccessToken>("getToken", "/token", {
      method: "POST",
      body: JSON.stringify({ grantType: "developer_key", scope })
    });
  }

  /**
   * Exchanges the developer key for a scope-narrowed token and uses it for subsequent calls.
   *
   * Prefer this in long-lived processes: the developer key is presented once instead of on
   * every request, and the resulting credential carries only the scopes asked for.
   */
  public async useNarrowedToken(scope: string): Promise<AegirAccessToken> {
    const token = await this.getToken(scope);
    this.accessToken = token.access_token;
    return token;
  }

  /** Checks whether a token is currently usable. Returns `{ active: false }` if not. */
  public async introspectToken(token: string): Promise<AegirIntrospection> {
    return await this.request<AegirIntrospection>("introspectToken", "/introspect", {
      method: "POST",
      body: JSON.stringify({ token })
    });
  }

  /** Revokes a token. Idempotent, and does not report whether the token was known. */
  public async revokeToken(token: string, reason?: string): Promise<void> {
    await this.request<unknown>("revokeToken", "/token/revoke", {
      method: "POST",
      body: JSON.stringify({ token, reason })
    });
  }

  public async scanIdentity(subjectId: string): Promise<ScanIdentityResult> {
    return await this.request<ScanIdentityResult>("scanIdentity", `/security/scan/${encodeURIComponent(subjectId)}`);
  }

  public async getIdentityGraph(subjectId: string): Promise<IdentityGraphSnapshot> {
    return await this.request<IdentityGraphSnapshot>("getIdentityGraph", `/security/graphs/${encodeURIComponent(subjectId)}`);
  }

  public async getIdentityGraphJson(subjectId: string): Promise<string> {
    const graph = await this.getIdentityGraph(subjectId);
    return JSON.stringify(graph);
  }

  public async getExposureSummary(subjectId: string): Promise<ExposureSummary> {
    return await this.request<ExposureSummary>("getExposureSummary", `/security/exposure/${encodeURIComponent(subjectId)}`);
  }

  public async performAction(request: PerformIdentityActionRequest): Promise<IdentityActionRecord> {
    return await this.request<IdentityActionRecord>("performAction", "/security/actions", {
      method: "POST",
      body: JSON.stringify(request)
    });
  }

  public async reverseAction(actionId: string, reason?: string): Promise<IdentityActionRecord> {
    const suffix = reason ? `?reason=${encodeURIComponent(reason)}` : "";
    return await this.request<IdentityActionRecord>("reverseAction", `/security/actions/${encodeURIComponent(actionId)}/reverse${suffix}`, {
      method: "POST"
    });
  }

  public async getActionHistory(subjectId: string): Promise<IdentityActionRecord[]> {
    return await this.request<IdentityActionRecord[]>("getActionHistory", `/security/actions/history/${encodeURIComponent(subjectId)}`);
  }

  // --- Canonical transactions ------------------------------------------------------------
  //
  // A transaction is opened before the protected operation, so a refused or abandoned attempt
  // is as auditable as a successful one. Nothing below creates one implicitly.

  /** Opens a transaction. Requires `transaction:write`. */
  public async createTransaction(request: {
    declaredAction: string;
    targetResourceId?: string;
    subjectPrincipalId?: string;
    externalCorrelationId?: string;
    lifetimeMinutes?: number;
  }): Promise<AegirTransaction> {
    return await this.request<AegirTransaction>("createTransaction", "/transactions", {
      method: "POST",
      body: JSON.stringify(request)
    });
  }

  /** Reads a transaction. Requires `transaction:read`. */
  public async getTransaction(transactionId: string): Promise<AegirTransaction> {
    return await this.request<AegirTransaction>(
      "getTransaction",
      `/transactions/${encodeURIComponent(transactionId)}`
    );
  }

  /** Reads a transaction's hash-chained event history. Requires `transaction:read`. */
  public async getTransactionEvents(transactionId: string): Promise<AegirTransactionEvent[]> {
    return await this.request<AegirTransactionEvent[]>(
      "getTransactionEvents",
      `/transactions/${encodeURIComponent(transactionId)}/events`
    );
  }

  /**
   * Issues a signed receipt for a transaction. Requires `transaction:read`.
   *
   * Audit authority is deliberately narrow: it proves what Aegir decided and did. It does not
   * resolve an opaque principal to a person, and it does not decrypt anything.
   */
  public async getTransactionReceipt(transactionId: string): Promise<AegirTransactionReceipt> {
    return await this.request<AegirTransactionReceipt>(
      "getTransactionReceipt",
      `/transactions/${encodeURIComponent(transactionId)}/receipt`
    );
  }

  /** Verifies a previously issued receipt, including whether its key was valid when it signed. */
  public async verifyTransactionReceipt(receipt: AegirTransactionReceipt): Promise<AegirReceiptVerification> {
    return await this.request<AegirReceiptVerification>(
      "verifyTransactionReceipt",
      "/transactions/receipt/verify",
      { method: "POST", body: JSON.stringify({ receipt }) }
    );
  }

  // --- AI agent identity -------------------------------------------------------------------

  /**
   * Registers an agent and returns its credential.
   *
   * `agentKey` is returned once and never again. Requires `agent:write`, which an agent itself
   * can never hold — an agent acts, it does not administer.
   */
  public async registerAgent(request: {
    displayName: string;
    providerId?: string;
    modelId?: string;
    applicationId?: string;
    scopes?: string[];
    lifetimeMinutes?: number;
  }): Promise<AegirAgentRegistration> {
    return await this.request<AegirAgentRegistration>("registerAgent", "/agents", {
      method: "POST",
      body: JSON.stringify(request)
    });
  }

  /** Lists agents owned by the caller's developer account. Requires `agent:read`. */
  public async listAgents(): Promise<AegirAgentRecord[]> {
    return await this.request<AegirAgentRecord[]>("listAgents", "/agents");
  }

  /** Revokes an agent. Requires `agent:write`. */
  public async revokeAgent(agentId: string): Promise<AegirAgentRecord> {
    return await this.request<AegirAgentRecord>(
      "revokeAgent",
      `/agents/${encodeURIComponent(agentId)}/revoke`,
      { method: "POST" }
    );
  }

  /** Exchanges an `agentId:secret` pair for an agent token and uses it for subsequent calls. */
  public async useAgentKey(agentKey: string, scope?: string): Promise<AegirAccessToken> {
    const token = await this.request<AegirAccessToken>("useAgentKey", "/token", {
      method: "POST",
      headers: { "X-Aegir-Agent-Key": agentKey },
      body: JSON.stringify({ grantType: "agent_key", scope })
    });

    this.accessToken = token.access_token;
    return token;
  }

  // --- Provider invocation -----------------------------------------------------------------

  /** Lists providers this deployment can invoke. Requires `agent:read`. */
  public async listProviders(): Promise<{ providerId: string }[]> {
    return await this.request<{ providerId: string }[]>("listProviders", "/providers");
  }

  /**
   * Binds an agent to a vendor credential. Requires `agent:write`.
   *
   * The key is encrypted at rest and never returned. Naming `allowedModelIds` narrows the agent
   * to the models its purpose requires.
   */
  public async bindProvider(
    agentId: string,
    request: { providerId: string; apiKey: string; allowedModelIds?: string[] }
  ): Promise<AegirProviderBinding> {
    return await this.request<AegirProviderBinding>(
      "bindProvider",
      `/agents/${encodeURIComponent(agentId)}/providers`,
      { method: "POST", body: JSON.stringify(request) }
    );
  }

  /**
   * Invokes a model provider as the authenticated agent. Requires `agent:invoke`.
   *
   * The acting identity comes from the token, never from this request. A vendor failure is
   * returned as `succeeded: false` with a normalized `errorKind` rather than thrown, so a
   * failed call is recorded exactly like a successful one.
   */
  public async invokeProvider(request: AegirInvokeProviderRequest): Promise<AegirInvocationResult> {
    return await this.request<AegirInvocationResult>("invokeProvider", "/ai/invocations", {
      method: "POST",
      body: JSON.stringify(request)
    });
  }

  // --- Protected agent-to-agent messaging --------------------------------------------------

  /**
   * Protects a payload to another agent and binds it to a transaction. Requires `agent:message`.
   *
   * The returned envelope is not transferable: moving it to a different transaction, sender,
   * recipient or action makes it fail validation.
   */
  public async sendAgentMessage(request: {
    transactionId: string;
    recipientAgentId: string;
    action: string;
    /** Base64 payload. */
    payload: string;
  }): Promise<AegirAgentMessage> {
    return await this.request<AegirAgentMessage>("sendAgentMessage", "/ai/messages", {
      method: "POST",
      body: JSON.stringify(request)
    });
  }

  /** Opens a protected message addressed to the authenticated agent. Requires `agent:message`. */
  public async receiveAgentMessage(message: AegirAgentMessage): Promise<AegirAgentMessageDelivery> {
    return await this.request<AegirAgentMessageDelivery>(
      "receiveAgentMessage",
      "/ai/messages/receive",
      { method: "POST", body: JSON.stringify(message) }
    );
  }

  private async request<T>(operation: string, path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");

    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    if (this.configKey) {
      headers.set("X-Aegir-Config-Key", this.configKey);
    }

    // A bearer token takes precedence: once one has been obtained there is no reason to keep
    // presenting the long-lived developer key on every request.
    if (this.accessToken) {
      headers.set("Authorization", `Bearer ${this.accessToken}`);
    } else if (this.developerKey) {
      headers.set("X-Aegir-Developer-Key", this.developerKey);
    }

    await this.emitTrace({
      traceName: "request.start",
      operation,
      tracePhase: "request.start",
      occurredAtUtc: new Date().toISOString(),
      correlationId: null,
      metadata: { path, method: init.method ?? "GET" }
    });
    await this.emitLog({
      level: "information",
      eventName: "request.start",
      message: `Starting ${operation}.`,
      operation,
      correlationId: null,
      occurredAtUtc: new Date().toISOString(),
      metadata: { path, method: init.method ?? "GET" }
    });

    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}/v1${path}`, {
        ...init,
        headers
      });
    } catch (error) {
      await this.emitMetric({
        metricName: "aegir.client.request.duration",
        value: 0,
        unit: "ms",
        observedAtUtc: new Date().toISOString(),
        dimensions: { operation, status: "0", errorCode: "transport_error" }
      });
      await this.emitTrace({
        traceName: "request.error",
        operation,
        tracePhase: "request.error",
        occurredAtUtc: new Date().toISOString(),
        correlationId: null,
        metadata: { errorCode: "transport_error" }
      });
      throw new AegirSecurityError(
        error instanceof Error ? error.message : "Aegir transport request failed.",
        0,
        "transport_error",
        null,
        null
      );
    }

    const text = await response.text();
    const body = text ? tryParseJson(text) : null;
    const correlationId = response.headers.get("X-Correlation-Id");
    const code = resolveErrorCode(response.status, body);

    await this.emitMetric({
      metricName: "aegir.client.request.duration",
      value: 0,
      unit: "ms",
      observedAtUtc: new Date().toISOString(),
      dimensions: { operation, status: String(response.status), errorCode: code }
    });

    if (!response.ok) {
      await this.emitLog({
        level: "error",
        eventName: "request.error",
        message: `Aegir request failed with status ${response.status}.`,
        operation,
        correlationId,
        occurredAtUtc: new Date().toISOString(),
        metadata: { errorCode: code, status: String(response.status) }
      });
      await this.emitTrace({
        traceName: "request.error",
        operation,
        tracePhase: "request.error",
        occurredAtUtc: new Date().toISOString(),
        correlationId,
        metadata: { errorCode: code, status: String(response.status) }
      });
      throw new AegirSecurityError(
        `Aegir request failed with status ${response.status}.`,
        response.status,
        code,
        correlationId,
        body
      );
    }

    await this.emitLog({
      level: "information",
      eventName: "request.complete",
      message: `Completed ${operation}.`,
      operation,
      correlationId,
      occurredAtUtc: new Date().toISOString(),
      metadata: { status: String(response.status) }
    });
    await this.emitTrace({
      traceName: "request.complete",
      operation,
      tracePhase: "request.complete",
      occurredAtUtc: new Date().toISOString(),
      correlationId,
      metadata: { status: String(response.status) }
    });

    return body as T;
  }

  private async emitLog(entry: AegirLogEntry): Promise<void> {
    await this.diagnosticsHooks?.log?.(entry);
  }

  private async emitMetric(event: AegirMetricEvent): Promise<void> {
    await this.diagnosticsHooks?.metric?.(event);
  }

  private async emitTrace(event: AegirTraceEvent): Promise<void> {
    await this.diagnosticsHooks?.trace?.(event);
  }
}

function tryParseJson(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    return input;
  }
}

function resolveErrorCode(status: number, body: unknown): AegirErrorCode {
  if (body && typeof body === "object") {
    const payload = body as Record<string, unknown>;
    const candidate = payload.code ?? payload.error;
    if (typeof candidate === "string" && candidate.length > 0) {
      return candidate as AegirErrorCode;
    }
  }

  switch (status) {
    case 400:
      return "invalid_request";
    case 401:
      return "unauthorized";
    case 403:
      return "forbidden";
    case 404:
      return "not_found";
    case 409:
      return "conflict";
    case 429:
      return "rate_limited";
    default:
      return status >= 500 ? "server_error" : "unknown_error";
  }
}

function computePayloadHash(canonicalPayload: string): string {
  return createHash("sha256").update(canonicalPayload, "utf8").digest("hex");
}

function createRuntimeId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
}

function buildBudgetKey(controlType: OperationalControlType, subjectKey: string): string {
  if (!subjectKey.trim()) {
    throw new Error("A subjectKey is required.");
  }

  return `${controlType}:${subjectKey.trim()}`;
}

function toBudgetEnvelope(
  controlType: OperationalControlType,
  subjectKey: string,
  state: { windowStartedAtUtc: number; consumed: number },
  windowMs: number,
  limit: number
): BudgetEnvelope {
  return {
    controlType,
    subjectKey: subjectKey.trim(),
    windowStartedAtUtc: new Date(state.windowStartedAtUtc).toISOString(),
    windowEndsAtUtc: new Date(state.windowStartedAtUtc + windowMs).toISOString(),
    limit,
    consumed: state.consumed,
    remaining: Math.max(limit - state.consumed, 0),
    isExhausted: state.consumed >= limit
  };
}

function signPayload(payload: Uint8Array, classicalMultiplier: number, pqcMultiplier: number): Uint8Array {
  const classical = computeDigest(payload, classicalMultiplier);
  const pqc = computeDigest(payload, pqcMultiplier);
  const signature = new Uint8Array(64);
  signature.set(classical, 0);
  signature.set(pqc, 32);
  return signature;
}

function verifyPayload(
  payload: Uint8Array,
  signature: Uint8Array,
  classicalMultiplier: number,
  pqcMultiplier: number
): boolean {
  if (signature.length < 64) {
    return false;
  }

  const expected = signPayload(payload, classicalMultiplier, pqcMultiplier);
  for (let index = 0; index < 64; index += 1) {
    if (signature[index] !== expected[index]) {
      return false;
    }
  }

  return true;
}

function computeDigest(payload: Uint8Array, multiplier: number): Uint8Array {
  if (payload.length === 0) {
    throw new Error("A payload is required.");
  }

  const state = new Uint8Array(32);

  for (let index = 0; index < 32; index += 1) {
    const payloadByte = payload[index % payload.length];
    state[index] = (payloadByte ^ wrapByte(multiplier * (index + 1))) & 0xff;
  }

  for (let index = 0; index < payload.length; index += 1) {
    const slot = index % 32;
    const payloadByte = payload[index];
    const rotated = rotateLeft(payloadByte, index % 8);
    state[slot] = wrapByte((state[slot] + rotated) * wrapByte(multiplier + (slot | 1)));
    const mirror = 31 - slot;
    state[mirror] = wrapByte(state[mirror] ^ wrapByte(payloadByte * (multiplier ^ wrapByte(index + 17))));
  }

  for (let round = 0; round < 6; round += 1) {
    for (let slot = 0; slot < 32; slot += 1) {
      const next = state[(slot + 1) % 32];
      const previous = state[(slot + 31) % 32];
      state[slot] = wrapByte(
        wrapByte(state[slot] + rotateLeft(next, 1))
        ^ wrapByte(previous + multiplier + round + slot)
      );
    }
  }

  return state;
}

function rotateLeft(value: number, amount: number): number {
  return wrapByte((value << amount) | (value >> (8 - amount)));
}

function wrapByte(value: number): number {
  return value & 0xff;
}
