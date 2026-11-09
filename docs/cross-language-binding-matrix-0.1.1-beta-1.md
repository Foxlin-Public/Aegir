# Cross-Language Binding Matrix

Foxlin Industries E1-D source-contract addition: the existing device-key registration operation is described in [device-keys.md](contracts/v1/device-keys.md) and OpenAPI v1. All five ecosystems share that HTTP definition; no new language convenience method, package release or native authenticator is supplied. Developer management-only registration and explicit fresh Human-owner approval remain distinct. Actual .NET App signed-handoff consumer validation is separate from portable SDK cryptographic availability.

> **Two notes before reading the table.**
>
> **Java and Go are not released in Beta-1.** Their columns describe source in this repository,
> not packages you can install. Only .NET, Node and Python ship.
>

> **AEG-RC1-R004:** portable signing/verification rows are deprecated fail-closed stubs,
> not cryptography. Sign throws (Go panics); verify returns false. SHA-256 is integrity only.
> See [the compatibility contract](cryptographic-contracts-rc1.md). Java/Go remain source-only.

Status: Parity complete after Batch 3D.

This document records the Batch 2C cross-language binding review for the intended Beta 1 public surface defined in `Docs/public-api-surface-0.1.1-beta.1.md`.

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
| `validateSafeEnvelope` / `ValidateSafeEnvelope` | Complete | Complete | Complete: `validate_safe_envelope` | Complete | Unsigned hash comparison only; isAuthenticated=false; rejects signatureEnvelope. |
| `SafeEnvelopeRecord` | Integrity-only | Integrity-only nested class | Integrity-only dataclass | Integrity-only struct | Historical .NET hash uses uppercase hex; these helpers use lowercase. No signed-envelope wire interoperability claim. |
| `SafeEnvelopeValidationResult` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `TrustCoreAlgorithmDescriptor` | Legacy metadata | Legacy nested class | Legacy dataclass | Legacy struct | These four use algorithmId/hybrid; .NET has a different legacy descriptor. None grants authority. |
| `TrustCoreSignatureEnvelope` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere; byte encoding should be formally specified for JSON. |
| `signChallengePayload` / `SignChallengePayload` | Retired | Retired | Retired: `sign_challenge_payload` | Retired | Deprecated: sign throws/panics; verify always false. No authority. |
| `verifyChallengePayload` / `VerifyChallengePayload` | Retired | Retired | Retired: `verify_challenge_payload` | Retired | Deprecated: sign throws/panics; verify always false. No authority. |
| `signProofReceiptPayload` / `SignProofReceiptPayload` | Retired | Retired | Retired: `sign_proof_receipt_payload` | Retired | Deprecated: sign throws/panics; verify always false. No authority. |
| `verifyProofReceiptPayload` / `VerifyProofReceiptPayload` | Retired | Retired | Retired: `verify_proof_receipt_payload` | Retired | Deprecated: sign throws/panics; verify always false. No authority. |
| `signIdentityTokenPayload` / `SignIdentityTokenPayload` | Retired | Retired | Retired: `sign_identity_token_payload` | Retired | Deprecated: sign throws/panics; verify always false. No authority. |
| `verifyIdentityTokenPayload` / `VerifyIdentityTokenPayload` | Retired | Retired | Retired: `verify_identity_token_payload` | Retired | Deprecated: sign throws/panics; verify always false. No authority. |
| `BudgetEnvelope` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `BudgetEnvelopeOptions` | Complete | Complete nested options DTO | Complete dataclass | Complete struct | Canonical defaults are `25/50/10/60000`. |
| `InMemoryBudgetEnvelopeService` | Complete | Complete nested class | Complete class | Complete constructor function plus type | Equivalent behavior exists everywhere. |
| `BudgetExhaustedError` / C# `BudgetExhaustedException` | Complete | Complete nested error | Complete | Complete | Equivalent exists; exception name differs in C#. |
| `AgentToAgentMessageRecord` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `AgentToAgentReceiveResult` | Complete | Complete nested class | Complete dataclass | Complete struct | Equivalent exists everywhere. |
| `InMemoryAgentToAgentProtocol` | Complete | Complete nested class | Complete class | Complete constructor function plus type | Equivalent behavior exists everywhere. |
| JSON serialization shapes for public DTOs | Complete | Complete typed DTOs/accessors | Complete | Complete via JSON tags | Wire shape compatible across SDKs. |
| Local SHA-256 integrity utility | `computePayloadDigest` | `PortableSecurity.computePayloadDigest` | `compute_payload_digest` | `ComputePayloadDigest` | Hash only; shared standard vectors. No PQC interoperability claim. |

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
5. SHA-256 integrity utilities and local A2A simulation exist across SDKs; retired authority helpers fail closed.


## E1-E MCP source contract

The custom HTTP MCP routes are modeled separately from SDK stdio. Historical E1-E contract:154 route identities,79 operations,116 reachable schemas; all original/B/C/D semantic anchors retained. See [MCP transport](contracts/v1/mcp-transport.md). Five-language direct HTTP consumers exercise current scoped discovery, initialization, durable exact-intent retry, changed-intent refusal and anonymous denial. This does not add typed MCP SDK methods or publish packages. Human delegation remains E2.
# Agent message qualification addendum

Foxlin Industries. Existing source Node/Python `sendAgentMessage` and `receiveAgentMessage` are qualified through their actual native HTTPS transports against the canonical Agent message backend. The shared [HTTP DTO contract](contracts/v1/agent-messages.md) is source documentation for all ecosystems; no additional .NET/Java/Go convenience API or package availability is claimed. Agent keys/JWTs authenticate each side; developer keys are insufficient. HTTP MCP has message adapters; SDK stdio retains its existing distinct tool list. Envelope formation/local opening, durable transaction evidence and external recipient effects are separate states.

# Signed handoff source contract addition

All five integration ecosystems may use the same eight existing HTTP contracts in
[signed-handoff.md](contracts/v1/signed-handoff.md). No new convenience methods or
published versions are claimed. Authentication uses a current RP backend relay
and exact current owner-approved device signature; native clients hold neither
RP backend credentials nor configuration secrets. Safe restart behavior is session
invalidation, requiring a new ceremony. The six adapter contracts are documented separately below.

# QR and launch adapters

All five ecosystems share the six existing HTTP source contracts in
[handoff-adapters.md](contracts/v1/handoff-adapters.md). No new convenience methods
or published packages are claimed. Use the original RP backend relay; QR locator
possession never proves Human authority. Mobile push is selection only, provider
choice is offered display metadata, and desktop links do not prove OS activation.



## C1 Skills source addendum

See [Skills HTTP MCP source contract](skills-mcp-source.md). The unreleased .NET integration source adds `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`; JavaScript/TypeScript, Python, Java and Go expose this C1 capability only through the raw HTTP contract, without typed C1 methods or claimed C1 native parity. It requires a newly consented `ags1_` reference and current Agent identity. Old no-Skill grants cannot execute Skills. Runtime HTTP registry:14 before filtering; SDK stdio registry:12 with no Skill runner. This source-only addition changes no SDK package version and authorizes no publication or deployment. Runtime qualification is recorded by exact source-bound acceptance receipts; deployment remains unaccepted.


## C2 installed Skills source addendum

The additive [Skills source contract](skills-mcp-source.md#c2-scoped-installation-and-installed-grants) models current Human installation management and separately consented installed grants. The .NET source explicitly selects `AegirSkillMcpClient.ForInstalledSkill` for new `ags2_` references; the default constructor retains C1 `ags1_` mode. All five ecosystems may use the raw installation HTTP contract; no typed management SDK or installed-Skill parity in the other four languages is claimed. Uninstall is terminal for that instance. Explicit reinstall creates a fresh identity and requires fresh execution consent. Package versions and publication status remain unchanged.


### C3 authentication configuration inspection source contract

| Surface | .NET | Node/TS | Python | Java | Go |
|---|---|---|---|---|---|
| Exact installed authentication inspection API | Typed source `AegirAuthenticationSkillApiClient` | Raw HTTP only | Raw HTTP only | Raw HTTP only | Raw HTTP only |
| Authentication Skill MCP/stdio executor | Unavailable | Unavailable | Unavailable | Unavailable | Unavailable |

See [bounded C3 contract](authentication-skill-source.md). Current selected app/group/resource authority and license are mandatory; no ceremony, factor recovery, passkey-only login, native mobile certification, secret custody, package publication or deployment. Original C1/C2 semantics are retained. Exact source-bound receipts govern acceptance.

C3 recovery integrity: after the exact authentication Skill version is first declared, supported PostgreSQL application create/save operations validate and advance the existing independent consent journal before SQL commit. Its fixed fingerprint covers application ID, developer, environment, status and UTC creation identity; it grants no permissions. Missing, mismatched or interrupted independent truth refuses with unavailable/unknown-reconcile semantics. Unconfigured imports or externally owned enrolled write transactions fail closed. No automatic witness repair or legacy approval is provided. The fingerprint is computed from bounded pages of fixed row digests while existing canonical admission fences application mutations; total scan/sort work still grows with retained applications. This is not a global creation quota, production-scale claim or universal rollback detector for developer/group/license/policy tables.


## C4 source-only authorization observation

`POST /v1/skills/v2/authorization-inspection` uses the [strict C4 source contract](authorization-skill-source.md) and exact current `ags2_` authority, original Human target and permission. .NET adds a source-only typed API client; Node/TypeScript, Python, Java and Go have raw HTTP only. No new MCP/stdio operation or distribution version. Implementation remains under source-bound qualification; no publication or deployment acceptance.


## C6 source-only Agent enrollment preparation

The [C6 source contract](agent-onboarding-skill-source.md) adds `POST /v1/skills/v2/agent-onboarding-preparation`, operation `application.agent-onboarding.prepare`, in original family `agent-onboarding`. .NET integration source provides `AegirAgentOnboardingSkillApiClient.PrepareAsync` and `ReconcileAsync`. Node/TypeScript, Python, Java and Go have the raw HTTP contract only; no typed C6 parity is claimed. Existing SDK package versions, twelve stdio tools and publication status are unchanged.

This is exact current installed-Skill/consent-bound preparation, not proposal creation, identity registration, issuance approval, credential activation, private-key custody, group membership or delegation. Existing identities cannot be adopted; unsupported prerequisites remain explicit. Full native adversarial qualification is pending; source-bound C6 receipts govern acceptance. No publication, deployment or production release is authorized.


## C7 source-only secure execution and receipt

The [C7 source contract](secure-execution-receipt-skill-source.md) adds `POST /v1/skills/v2/secure-execution` for the bounded canonical group administrative metadata read. .NET integration source offers `AegirSecureExecutionSkillApiClient.ExecuteAsync` / `ReconcileAsync` and `AegirSecureExecutionReceiptVerifier`; Node/TypeScript, Python, Java and Go use raw HTTP only. This source profile adds no MCP/stdio tool, package version or registry publication.

The ML-DSA-65 artifact binds a committed read to its exact original operation and approved authority context. Public verification requires a separately trusted public key, lifecycle facts and operation/tenant/Agent/root/grant/resource context. It proves artifact cryptography under those assumptions; current authority, independent SQL truth, client delivery and external effects require separate evidence. Exact C7 source-bound runtime/review receipts govern acceptance. Production verifier distribution remains unqualified.
