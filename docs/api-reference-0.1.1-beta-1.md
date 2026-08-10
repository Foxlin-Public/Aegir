# Aegir API Reference v0.1.1-beta.1

Status: Beta-1 public API reference.

This reference documents only the finalized public SDK surface. Host/runtime/admin/developer/KYC/device/OIDC/proof-ledger/storage/billing/recovery/organization/trust-token/persistence APIs are excluded.

## Security Client

### C# / .NET

Namespace: `Foxlin.Aegir.Auth.Services`

Primary types:

- `IAegirSecurityProvider`
- `AegirSecurityProvider`
- `AegirSecurityHttpClient`
- `AegirSecurityClientOptions`
- `AegirSecurityClientException`

Method signatures:

| Method | Parameters | Return | Errors |
| --- | --- | --- | --- |
| `ScanIdentityAsync` | `string subjectId`, optional `CancellationToken` | `ValueTask<ScanIdentityResult>` | `AegirSecurityClientException` for HTTP/transport failures |
| `GetIdentityGraphAsync` | `string subjectId`, optional `CancellationToken` | `ValueTask<IdentityGraphSnapshot>` | `AegirSecurityClientException` |
| `GetIdentityGraphJsonAsync` | `string subjectId`, optional `CancellationToken` | `ValueTask<string>` | `AegirSecurityClientException`, JSON serialization errors |
| `GetExposureSummaryAsync` | `string subjectId`, optional `CancellationToken` | `ValueTask<ExposureSummary>` | `AegirSecurityClientException` |
| `PerformActionAsync` | `PerformIdentityActionRequest request`, optional `CancellationToken` | `ValueTask<IdentityActionRecord>` | `AegirSecurityClientException` |
| `ReverseActionAsync` | `string actionId`, optional `string reason`, optional `CancellationToken` | `ValueTask<IdentityActionRecord>` | `AegirSecurityClientException` |
| `GetActionHistoryAsync` | `string subjectId`, optional `CancellationToken` | `ValueTask<IReadOnlyList<IdentityActionRecord>>` | `AegirSecurityClientException` |

Options:

- `BaseUrl: string`
- `ConfigKey: string?`
- `DeveloperKey: string?`
- `HttpClient: HttpClient?`
- `DiagnosticsSink: IAegirClientDiagnosticsSink?`

### TypeScript / npm

Module: `@foxlin_industries/aegir-security`

Primary types:

- `AegirSecurityClient`
- `AegirSecurityClientOptions`
- `AegirSecurityError`

Method signatures:

| Method | Parameters | Return | Errors |
| --- | --- | --- | --- |
| `scanIdentity` | `subjectId: string` | `Promise<ScanIdentityResult>` | `AegirSecurityError` |
| `getIdentityGraph` | `subjectId: string` | `Promise<IdentityGraphSnapshot>` | `AegirSecurityError` |
| `getIdentityGraphJson` | `subjectId: string` | `Promise<string>` | `AegirSecurityError` |
| `getExposureSummary` | `subjectId: string` | `Promise<ExposureSummary>` | `AegirSecurityError` |
| `performAction` | `request: PerformIdentityActionRequest` | `Promise<IdentityActionRecord>` | `AegirSecurityError` |
| `reverseAction` | `actionId: string`, optional `reason?: string` | `Promise<IdentityActionRecord>` | `AegirSecurityError` |
| `getActionHistory` | `subjectId: string` | `Promise<IdentityActionRecord[]>` | `AegirSecurityError` |

Options:

- `baseUrl: string`
- `configKey?: string`
- `developerKey?: string`
- `fetch?: typeof fetch`
- `diagnosticsHooks?: AegirDiagnosticsHooks`

### Java / Maven

Package: `cloud.foxlin.aegir.security`

Primary types:

- `AegirSecurityClient`
- `AegirSecurityError`
- `AegirDiagnosticsHooks`
- `PerformIdentityActionRequest`
- `SecurityModels`

Method signatures:

| Method | Parameters | Return | Errors |
| --- | --- | --- | --- |
| `scanIdentity` | `String subjectId` | `SecurityModels.ScanIdentityResult` | `IOException`, `InterruptedException`, `AegirSecurityError` |
| `getIdentityGraph` | `String subjectId` | `SecurityModels.IdentityGraphSnapshot` | `IOException`, `InterruptedException`, `AegirSecurityError` |
| `getIdentityGraphJson` | `String subjectId` | `String` | `IOException`, `InterruptedException`, `AegirSecurityError` |
| `getExposureSummary` | `String subjectId` | `SecurityModels.ExposureSummary` | `IOException`, `InterruptedException`, `AegirSecurityError` |
| `performAction` | `PerformIdentityActionRequest request` | `SecurityModels.IdentityActionRecord` | `IOException`, `InterruptedException`, `AegirSecurityError` |
| `reverseAction` | `String actionId`, nullable `String reason` | `SecurityModels.IdentityActionRecord` | `IOException`, `InterruptedException`, `AegirSecurityError` |
| `getActionHistory` | `String subjectId` | `List<SecurityModels.IdentityActionRecord>` | `IOException`, `InterruptedException`, `AegirSecurityError` |

Constructors:

- `AegirSecurityClient(String baseUrl, String configKey, String developerKey)`
- `AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient httpClient)`
- `AegirSecurityClient(String baseUrl, String configKey, String developerKey, HttpClient httpClient, AegirDiagnosticsHooks diagnosticsHooks)`

### Python / PyPI

Module: `foxlin_aegir_security`

Primary types:

- `AegirSecurityClient`
- `AegirSecurityError`
- `AegirDiagnosticsHooks`

Method signatures:

| Method | Parameters | Return | Errors |
| --- | --- | --- | --- |
| `scanIdentity` | `subjectId: str` | `ScanIdentityResult` | `AegirSecurityError` |
| `getIdentityGraph` | `subjectId: str` | `IdentityGraphSnapshot` | `AegirSecurityError` |
| `getIdentityGraphJson` | `subjectId: str` | `str` | `AegirSecurityError` |
| `getExposureSummary` | `subjectId: str` | `ExposureSummary` | `AegirSecurityError` |
| `performAction` | `action: PerformIdentityActionRequest` | `IdentityActionRecord` | `AegirSecurityError` |
| `reverseAction` | `actionId: str`, optional `reason: str | None` | `IdentityActionRecord` | `AegirSecurityError` |
| `getActionHistory` | `subjectId: str` | `list[IdentityActionRecord]` | `AegirSecurityError` |

Constructor parameters:

- `base_url: str`
- `config_key: str | None`
- `developer_key: str | None`
- `transport`
- `diagnostics_hooks: AegirDiagnosticsHooks | None`

### Go

Package: `aegirsecurity`

Module: `foxlin/aegir-security-go`

Primary types:

- `AegirSecurityClient`
- `ClientOptions`
- `AegirSecurityError`
- `DiagnosticsHooks`

Method signatures:

| Method | Parameters | Return | Errors |
| --- | --- | --- | --- |
| `ScanIdentity` | `subjectID string` | `(*ScanIdentityResult, error)` | `*AegirSecurityError` or transport error |
| `GetIdentityGraph` | `subjectID string` | `(*IdentityGraphSnapshot, error)` | `*AegirSecurityError` or transport error |
| `GetIdentityGraphJSON` | `subjectID string` | `(string, error)` | `*AegirSecurityError` or transport error |
| `GetExposureSummary` | `subjectID string` | `(*ExposureSummary, error)` | `*AegirSecurityError` or transport error |
| `PerformAction` | `PerformIdentityActionRequest` | `(*IdentityActionRecord, error)` | `*AegirSecurityError` or transport error |
| `ReverseAction` | `actionID string`, `reason *string` | `(*IdentityActionRecord, error)` | `*AegirSecurityError` or transport error |
| `GetActionHistory` | `subjectID string` | `([]IdentityActionRecord, error)` | `*AegirSecurityError` or transport error |

Constructors:

- `NewAegirSecurityClient(baseURL, configKey, developerKey string, httpClient HTTPDoer) *AegirSecurityClient`
- `NewAegirSecurityClientWithOptions(options ClientOptions) *AegirSecurityClient`

## Public Model Shapes

All SDKs use the following JSON wire shapes.

### `ScanIdentityResult`

| Field | Shape |
| --- | --- |
| `subjectId` | `string` |
| `graph` | `IdentityGraphSnapshot` |
| `exposure` | `ExposureSummary` |
| `actionHistory` | array/list of `IdentityActionRecord` |

### `IdentityGraphSnapshot`

| Field | Shape |
| --- | --- |
| `graphId` | `string` |
| `generatedAtUtc` | ISO-8601 UTC timestamp string |
| `scores` | `IdentityGraphScores` |
| `nodes` | array/list of `IdentityGraphNode` |
| `edges` | array/list of `IdentityGraphEdge` |
| `metadata` | string map/dictionary |

### `IdentityGraphNode`

Fields: `nodeId`, `nodeType`, `displayName`, `status`, `trustTier`, `observedAtUtc`, nullable `lastVerifiedAtUtc`, `metadata`.

### `IdentityGraphEdge`

Fields: `edgeId`, `edgeType`, `fromNodeId`, `toNodeId`, `status`, `trustWeight`, `evidenceType`, `reason`, `observedAtUtc`, nullable `lastVerifiedAtUtc`, `metadata`.

### `IdentityGraphScores`

Fields: `exposureScore`, `trustScore`, `connectionClarityScore`.

### `ExposureSummary`

Fields: `graphId`, `generatedAtUtc`, `exposureScore`, `findings`, `summaryText`.

### `ExposureFinding`

Fields: `findingId`, `category`, `severity`, `summary`, nullable `nodeId`, nullable `edgeId`, `metadata`.

### `PerformIdentityActionRequest`

Fields: `subjectId`, `actionType`, optional `targetNodeId`, optional `reason`.

### `IdentityActionRecord`

Fields: `actionId`, `subjectId`, `actionType`, `status`, nullable `targetNodeId`, nullable `reason`, `requestedAtUtc`, nullable `reversedAtUtc`, nullable `reverseReason`, `metadata`.

## Typed Enums

`IdentityActionType`: `LockIdentity`, `DisconnectService`, `VerifyConnection`, `RequestClarity`.

`IdentityActionStatus`: `Completed`, `Reversed`.

`IdentityGraphNodeType`: `Platform`, `Developer`, `DeveloperKey`, `Application`, `Environment`, `User`, `Device`, `Credential`, `Challenge`, `Token`, `AuditAnchor`, `PolicyScope`, `ExternalService`.

`IdentityGraphEdgeType`: `Owns`, `Issued`, `Registered`, `BelongsTo`, `AuthorizedFor`, `ScopedTo`, `Uses`, `PresentedBy`, `DerivedFrom`, `ApprovedBy`, `RevokedBy`, `AnchoredBy`, `ConnectedTo`, `ObservedOn`.

`ExposureFindingCategory`: `WeakConnection`, `UnknownConnection`, `StaleCredential`, `HighRiskLinkage`.

`ExposureFindingSeverity`: `Low`, `Medium`, `High`.

`AegirErrorCode`: `invalid_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `rate_limited`, `budget_exhausted`, `server_error`, `transport_error`, `unknown_error`.

## Diagnostics

Diagnostics hook shape:

- Log: `level`, `eventName`, `message`, `operation`, nullable `correlationId`, `occurredAtUtc`, `metadata`.
- Metric: `metricName`, `value`, `unit`, `observedAtUtc`, `dimensions`.
- Trace: `traceName`, `operation`, `tracePhase`, `occurredAtUtc`, nullable `correlationId`, `metadata`.

Language names:

- C#: `IAegirClientDiagnosticsSink`, `AegirClientLogEntry`, `AegirMetricEvent`, `AegirTraceEvent`.
- TypeScript: `AegirDiagnosticsHooks`, `AegirLogEntry`, `AegirMetricEvent`, `AegirTraceEvent`.
- Java: `AegirDiagnosticsHooks.LogEntry`, `AegirDiagnosticsHooks.MetricEvent`, `AegirDiagnosticsHooks.TraceEvent`.
- Python: `AegirDiagnosticsHooks` callback payload dictionaries.
- Go: `DiagnosticsHooks`, `LogEntry`, `MetricEvent`, `TraceEvent`; aliases exist for `AegirLogEntry`, `AegirMetricEvent`, and `AegirTraceEvent`.

## Portable Security

### Safe Envelopes

Public operations:

- C#: `ISafeEnvelopeService.CreateAsync`, `ISafeEnvelopeService.ValidateAsync`, plus `AegirPortableSecurity.CreateSafeEnvelopeAsync` and `AegirPortableSecurity.ValidateSafeEnvelopeAsync`
- TypeScript: `createSafeEnvelope`, `validateSafeEnvelope`
- Java: `PortableSecurity.createSafeEnvelope`, `PortableSecurity.validateSafeEnvelope`
- Python: `create_safe_envelope`, `validate_safe_envelope`
- Go: `CreateSafeEnvelope`, `ValidateSafeEnvelope`

Models:

- `TrustCoreAlgorithmDescriptor`: `name`, `version`, `parameters`.
- `TrustCoreSignatureEnvelope`: `classicalAlgorithm`, `postQuantumAlgorithm`, `classicalSignature`, `postQuantumSignature`, `metadata`.
- `SafeEnvelopeRecord`: `envelopeId`, `payloadType`, `canonicalPayload`, `payloadHash`, `createdAtUtc`, nullable `signatureEnvelope`.
- `SafeEnvelopeValidationResult`: `isValid`, `reason`, `payloadHash`.

### Trust-Core Helpers

Public operations:

- Challenge payload: sign and verify.
- Proof-receipt payload: sign and verify. *(deprecated: keyless digest, not proof of possession - Aegir signs receipts with ML-DSA-65 server-side)*
- Identity-token payload: sign and verify.

Input shape is bytes in C#, TypeScript, Java, Python, and Go. Return shape is bytes for sign operations and boolean for verify operations.

## Budget

`BudgetEnvelopeOptions` canonical defaults:

| Field | Default |
| --- | ---: |
| `identityScanLimit` / `IdentityScanLimit` | `25` |
| `externalLookupLimit` / `ExternalLookupLimit` | `50` |
| `connectionGraphRebuildLimit` / `ConnectionGraphRebuildLimit` | `10` |
| `windowMs` / `WindowMS` | `60000` |

`BudgetEnvelope` fields: `controlType`, `subjectKey`, `windowStartedAtUtc`, `windowEndsAtUtc`, `limit`, `consumed`, `remaining`, `isExhausted`.

Budget operations:

- C#: `IBudgetEnvelopeService.GetEnvelopeAsync`, `ConsumeAsync`
- TypeScript: `InMemoryBudgetEnvelopeService.getEnvelope`, `consume`
- Java: `PortableSecurity.InMemoryBudgetEnvelopeService.getEnvelope`, `consume`
- Python: `InMemoryBudgetEnvelopeService.get_envelope`, `consume`
- Go: `InMemoryBudgetEnvelopeService.GetEnvelope`, `Consume`

## Agent-To-Agent Protocol

Models:

- `AgentToAgentMessageRecord`: `messageId`, `senderAgentId`, `recipientAgentId`, `messageType`, nullable `correlationId`, `envelope`, `sentAtUtc`, nullable `receivedAtUtc`.
- `AgentToAgentReceiveResult`: `accepted`, `reason`, nullable `message`.

Operations:

- Send message.
- Get inbox.
- Receive message.

Receive reasons:

- `accepted`
- `message_not_found`
- `payload_hash_mismatch`
- `signature_missing`
