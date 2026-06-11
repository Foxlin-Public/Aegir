# Cross-Language Binding Matrix v0.1.1-beta-1

Status: Parity complete after Batch 3D.

This document records the Batch 2C cross-language binding review for the intended Beta 1 public surface defined in `Docs/public-api-surface-0.1.1-beta-1.md`.

## Review Inputs

- C# public surface: `src/Foxlin.Aegir.Auth`, `src/Foxlin.Aegir.Api`, `src/Foxlin.Aegir.App`, `src/Foxlin.Aegir.Web`, `src/Foxlin.Aegir.Mcp`
- TypeScript SDK: `src/Foxlin.Aegir.Npm/src/index.ts`
- Java SDK: `src/Foxlin.Aegir.Java/src/main/java/cloud/foxlin/aegir/security`
- Python SDK: `src/Foxlin.Aegir.Python/foxlin_aegir_security`
- Go SDK: `src/Foxlin.Aegir.Go`

## Parity Legend

- Complete: equivalent API exists with compatible behavior and wire shape.
- Partial: API exists but has naming, signature, return type, error, or model-shape differences that need an explicit decision.
- Missing: no equivalent API or model was found.
- Internalize C#: C# exposes an API that is not intended to be in the Beta 1 SDK contract and should be made internal or moved behind a documented host-extension boundary.

## Cross-Language Parity Matrix

| Intended Beta 1 API/model | TypeScript | Java | Python | Go | Finding |
| --- | --- | --- | --- | --- | --- |
| Security client construction/options | Complete: `AegirSecurityClient`, `AegirSecurityClientOptions` | Complete: `AegirSecurityClient` constructors | Complete: `AegirSecurityClient` constructor | Complete: `AegirSecurityClient`, `ClientOptions` | Exists everywhere; Go officially uses `AegirSecurityClient`. |
| `scanIdentity` / `ScanIdentityAsync` | Complete | Complete | Complete: `scan_identity` | Complete: `ScanIdentity` | Method and route parity present; idiomatic names differ. |
| `getIdentityGraph` / `GetIdentityGraphAsync` | Complete | Complete | Complete: `get_identity_graph` | Complete: `GetIdentityGraph` | Method parity present. |
| `getIdentityGraphJson` / `GetIdentityGraphJsonAsync` | Complete | Complete | Complete: `get_identity_graph_json` | Complete: `GetIdentityGraphJSON` | Method parity present; Go uses `JSON` acronym casing. |
| `getExposureSummary` / `GetExposureSummaryAsync` | Complete | Complete | Complete: `get_exposure_summary` | Complete: `GetExposureSummary` | Method parity present. |
| `performAction` / `PerformActionAsync` | Complete | Complete | Complete: `perform_action` | Complete: `PerformAction` | Method parity present. |
| `reverseAction` / `ReverseActionAsync` | Complete: optional `reason` | Complete: nullable `reason`; request body omitted, reason in query | Complete: optional `reason` | Complete: `*string` reason | Method parity present; reason transport shape should be frozen. |
| `getActionHistory` / `GetActionHistoryAsync` | Complete | Complete | Complete: `get_action_history` | Complete: `GetActionHistory` | Method parity present. |
| `ScanIdentityResult` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `IdentityGraphSnapshot` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `IdentityGraphNode` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `IdentityGraphEdge` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `IdentityGraphScores` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `ExposureSummary` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `ExposureFinding` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `PerformIdentityActionRequest` | Complete typed interface | Complete dedicated request class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `IdentityActionRecord` | Complete typed interface | Complete typed model/accessors | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| Identity action enum/status values | Complete typed unions | Complete enums | Complete `StrEnum` values | Complete typed string constants | Wire values match across SDKs. |
| Exposure/category/severity/node/edge enums | Complete typed unions | Complete enums | Complete `StrEnum` values | Complete typed string constants | Wire values match across SDKs. |
| `AegirSecurityError` / client error wrapper | Complete | Complete | Complete | Complete | Exists everywhere; error code/status/body/correlation fields need formal parity spec. |
| `AegirErrorCode` | Complete typed union | Complete enum plus `getErrorCode()` | Complete `StrEnum` | Complete typed string constants | Typed error-code behavior exists everywhere. |
| Diagnostics hooks | Complete: `log`, `metric`, `trace` hooks | Complete class/hooks with documented nested event types | Complete hooks | Complete hooks with idiomatic names plus `Aegir*` aliases | Diagnostics exist everywhere with documented naming. |
| `AegirLogEntry` | Complete | Complete nested `LogEntry` documented as official Java naming | Complete | Complete: `LogEntry` plus `AegirLogEntry` alias | Shape exists everywhere. |
| `AegirMetricEvent` | Complete | Complete nested `MetricEvent` documented as official Java naming | Complete | Complete: `MetricEvent` plus `AegirMetricEvent` alias | Shape exists everywhere. |
| `AegirTraceEvent` | Complete | Complete nested `TraceEvent` documented as official Java naming | Complete | Complete: `TraceEvent` plus `AegirTraceEvent` alias | Shape exists everywhere. |
| `createSafeEnvelope` / `CreateSafeEnvelope` | Complete | Complete | Complete: `create_safe_envelope` | Complete | Exists everywhere; error model differs by language. |
| `validateSafeEnvelope` / `ValidateSafeEnvelope` | Complete | Complete | Complete: `validate_safe_envelope` | Complete | Exists everywhere. |
| `SafeEnvelopeRecord` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `SafeEnvelopeValidationResult` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `TrustCoreAlgorithmDescriptor` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `TrustCoreSignatureEnvelope` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere; byte encoding should be formally specified for JSON. |
| `signChallengePayload` / `SignChallengePayload` | Complete | Complete | Complete: `sign_challenge_payload` | Complete | Exists everywhere. |
| `verifyChallengePayload` / `VerifyChallengePayload` | Complete | Complete | Complete: `verify_challenge_payload` | Complete | Exists everywhere. |
| `signProofReceiptPayload` / `SignProofReceiptPayload` | Complete | Complete | Complete: `sign_proof_receipt_payload` | Complete | Exists everywhere. |
| `verifyProofReceiptPayload` / `VerifyProofReceiptPayload` | Complete | Complete | Complete: `verify_proof_receipt_payload` | Complete | Exists everywhere. |
| `signIdentityTokenPayload` / `SignIdentityTokenPayload` | Complete | Complete | Complete: `sign_identity_token_payload` | Complete | Exists everywhere. |
| `verifyIdentityTokenPayload` / `VerifyIdentityTokenPayload` | Complete | Complete | Complete: `verify_identity_token_payload` | Complete | Exists everywhere. |
| `BudgetEnvelope` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `BudgetEnvelopeOptions` | Complete | Complete nested options DTO | Complete dataclass | Complete struct | Canonical defaults are `25/50/10/60000`. |
| `InMemoryBudgetEnvelopeService` | Complete | Complete nested class | Complete class | Complete constructor function plus type | Equivalent behavior exists everywhere. |
| `BudgetExhaustedError` / C# `BudgetExhaustedException` | Complete | Complete nested error | Complete | Complete | Equivalent exists; exception name differs in C#. |
| `AgentToAgentMessageRecord` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `AgentToAgentReceiveResult` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `InMemoryAgentToAgentProtocol` | Complete | Complete nested class | Complete class | Complete constructor function plus type | Equivalent behavior exists everywhere. |
| JSON serialization shapes for public DTOs | Complete | Complete typed DTOs/accessors | Complete | Complete via JSON tags | Wire shape compatible across SDKs. |
| Cryptographic behavior for portable signing/envelope helpers | Complete | Complete | Complete | Complete | Static helper names and behavior exist in all SDKs. Cross-language tests should remain the authority. |

## C# Public APIs That Should Be Internalized Or Explicitly Reclassified

The following C# public areas exceed the compact Beta 1 SDK contract and do not have cross-language bindings:

- Admin authorization, admin runtime stores, admin DTOs, group/license/moderation APIs.
- Developer account, developer key, developer commercial, pricing, billing, invoice, usage, checkout, and assignment APIs.
- KYC identity, KYC risk, vendor microservice, research, sanctions, age claims, parental consent, and geographic policy APIs.
- Device bootstrap, device management, device intelligence/fingerprint, secondary enrollment, native device bridge APIs.
- OIDC bridge, OIDC token mapping, OIDC code stores/generators, auth handoff, federation, and portal session APIs.
- Trust-token issuer/validator/authentication handler, nonce replay, token entropy, trust record stores, and hot-path security state APIs.
- Proof-ledger coordinator/exporter/store/batch/seal/receipt APIs.
- Storage policy, local encrypted store contracts, Postgres/Redis adapters, relational value readers, and database bootstrappers.
- Runtime workspaces, app platform services, web page models, web credential stores, MCP host/runtime objects.
- Serializer implementation classes and source-generation contexts, unless declared as host-extension APIs.

## Binding Verdict

`All cross-language bindings implemented` is complete after Batch 3D.

Reasons:

1. Public security client methods exist across C#, TypeScript, Java, Python, and Go.
2. Public DTOs and enum wire values are represented in every SDK.
3. Error-code and diagnostics behavior is implemented and documented across SDKs.
4. Budget options use one canonical shape and aligned defaults across SDKs.
5. Portable crypto helpers and A2A protocol types exist across SDKs.
