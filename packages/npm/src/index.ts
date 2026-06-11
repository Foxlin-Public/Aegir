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

export interface AegirSecurityClientOptions {
  baseUrl: string;
  configKey?: string;
  developerKey?: string;
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
  private readonly fetcher: typeof fetch;
  private readonly diagnosticsHooks?: AegirDiagnosticsHooks;

  public constructor(options: AegirSecurityClientOptions) {
    if (!options?.baseUrl?.trim()) {
      throw new Error("A baseUrl is required.");
    }

    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.configKey = options.configKey;
    this.developerKey = options.developerKey;
    this.fetcher = options.fetcher ?? globalThis.fetch;
    this.diagnosticsHooks = options.diagnosticsHooks;

    if (!this.fetcher) {
      throw new Error("A fetch implementation is required.");
    }
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

  private async request<T>(operation: string, path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");

    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    if (this.configKey) {
      headers.set("X-Aegir-Config-Key", this.configKey);
    }

    if (this.developerKey) {
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
