# Public API Surface v0.1.1-beta.1 (Final)

Status: Final Beta 1 public surface defined and C# visibility reduced to match the compact SDK contract.

This document is the Batch 2C-F public/internal reclassification pass. It uses:

- `Docs/public-api-surface-0.1.1-beta.1.md`
- `Docs/cross-language-binding-matrix-0.1.1-beta-1.md`
- `Docs/subsystem-boundaries-0.1.1-beta.1.md`

The final Beta 1 surface is the compact SDK contract. Host/runtime/admin/developer/KYC/device/OIDC/proof-ledger/storage/billing implementation APIs are excluded from the public surface.

## Final Public API Surface

### C# / .NET

Namespace: `Foxlin.Aegir.Auth.Services`

Keep public:

- `IAegirSecurityProvider`
  - `ScanIdentityAsync(string subjectId, CancellationToken cancellationToken = default)`
  - `GetIdentityGraphAsync(string subjectId, CancellationToken cancellationToken = default)`
  - `GetIdentityGraphJsonAsync(string subjectId, CancellationToken cancellationToken = default)`
  - `GetExposureSummaryAsync(string subjectId, CancellationToken cancellationToken = default)`
  - `PerformActionAsync(PerformIdentityActionRequest request, CancellationToken cancellationToken = default)`
  - `ReverseActionAsync(string actionId, string? reason = null, CancellationToken cancellationToken = default)`
  - `GetActionHistoryAsync(string subjectId, CancellationToken cancellationToken = default)`
- `AegirSecurityProvider`
- `AegirSecurityHttpClient`
- `AegirSecurityClientOptions`
- `AegirSecurityClientException`
- `AegirPortableSecurity`
- `IAegirClientDiagnosticsSink`
- `NullAegirClientDiagnosticsSink`
- `ISafeEnvelopeService`
- `SafeEnvelopeService`
- `IBudgetEnvelopeService`
- `InMemoryBudgetEnvelopeService`
- `BudgetEnvelopeOptions`
- `BudgetExhaustedException`
- `IAgentToAgentProtocol`
- `InMemoryAgentToAgentProtocol`

Namespace: `Foxlin.Aegir.Auth.Models`

Keep public:

- Security client result/request models:
  - `ScanIdentityResult`
  - `IdentityGraphSnapshot`
  - `IdentityGraphNode`
  - `IdentityGraphEdge`
  - `IdentityGraphScores`
  - `ExposureSummary`
  - `ExposureFinding`
  - `PerformIdentityActionRequest`
  - `IdentityActionRecord`
- Public enums required by those models:
  - `IdentityActionType`
  - `IdentityActionStatus`
  - `IdentityGraphNodeType`
  - `IdentityGraphEdgeType`
  - `ExposureFindingCategory`
  - `ExposureFindingSeverity`
- Diagnostics models:
  - `AegirClientLogEntry`
  - `AegirClientLogLevel`
  - `AegirMetricEvent`
  - `AegirTraceEvent`
- Portable security models:
  - `TrustCoreAlgorithmDescriptor`
  - `TrustCoreSignatureEnvelope`
  - `SafeEnvelopeRecord`
  - `SafeEnvelopeValidationResult`
- Budget/A2A models:
- `BudgetEnvelope`
- `BudgetEnvelopeOptions`
- `OperationalControlType`
  - `AgentToAgentMessageRecord`
  - `AgentToAgentReceiveResult`

Host/runtime APIs are no longer part of the C# public SDK surface. The host projects keep only their ASP.NET `Program` entry points public for integration-test hosting.

### TypeScript / npm

Module: package root.

Keep public:

- `AegirSecurityClient`
- `AegirSecurityClientOptions`
- `AegirSecurityError`
- `AegirErrorCode`
- `BudgetExhaustedError`
- `AegirDiagnosticsHooks`
- `AegirLogEntry`
- `AegirMetricEvent`
- `AegirTraceEvent`
- identity graph/action/exposure interfaces matching the C# keep-public model list
- `TrustCoreAlgorithmDescriptor`
- `TrustCoreSignatureEnvelope`
- `SafeEnvelopeRecord`
- `SafeEnvelopeValidationResult`
- `createSafeEnvelope`
- `validateSafeEnvelope`
- `computePayloadDigest` — SHA-256 integrity utility, no authority
- `signChallengePayload`
- `verifyChallengePayload`
- `signProofReceiptPayload` *(deprecated fail-closed stub, see below)*
- `verifyProofReceiptPayload`
- `signIdentityTokenPayload`
- `verifyIdentityTokenPayload`
- `BudgetEnvelope`
- `BudgetEnvelopeOptions`
- `InMemoryBudgetEnvelopeService`
- `AgentToAgentMessageRecord`
- `AgentToAgentReceiveResult`
- `InMemoryAgentToAgentProtocol`

### Java / Maven

Package: `cloud.foxlin.aegir.security`.

Keep public:

- `AegirSecurityClient`
- `AegirSecurityError`
- `AegirDiagnosticsHooks`
- `PerformIdentityActionRequest`
- `SecurityModels`
- `PortableSecurity`
- `PortableSecurity.BudgetEnvelopeOptions`

Completed SDK additions for parity:

- First-class typed Java DTOs or full accessors for:
  - `IdentityGraphNode`
  - `IdentityGraphEdge`
  - `IdentityGraphScores`
  - `ExposureFinding`
  - complete `IdentityGraphSnapshot`
  - complete `ExposureSummary`
  - complete `IdentityActionRecord`

### Python / PyPI

Module: `foxlin_aegir_security`.

Keep public:

- `AegirSecurityClient`
- `AegirDiagnosticsHooks`
- `AegirSecurityError`
- `BudgetExhaustedError`
- identity graph/action/exposure dataclasses matching the C# keep-public model list
- portable trust-core/safe-envelope dataclasses and helpers
- budget envelope dataclasses/service
- `BudgetEnvelopeOptions`
- A2A dataclasses/protocol

### Go

Package: `aegirsecurity`.

Keep public:

- `AegirSecurityClient`
- `ClientOptions`
- `NewAegirSecurityClient`
- `NewAegirSecurityClientWithOptions`
- `AegirSecurityError`
- `DiagnosticsHooks`
- `LogEntry`
- `MetricEvent`
- `TraceEvent`
- identity graph/action/exposure structs matching the C# keep-public model list
- portable trust-core/safe-envelope structs and helpers
- budget envelope structs/service
- `BudgetEnvelopeOptions`
- A2A structs/protocol

Completed consolidation for documentation freeze:

- Spec language uses the actual Go `AegirSecurityClient`.
- Go diagnostics keep idiomatic `LogEntry`, `MetricEvent`, and `TraceEvent` names, with `AegirLogEntry`, `AegirMetricEvent`, and `AegirTraceEvent` aliases exported for naming parity.

## APIs Internalized

The following C# APIs are not part of the compact SDK contract and were made `internal`, left public only as ASP.NET `Program` entry points, or hidden behind `InternalsVisibleTo` for host/test assemblies.

### Entire Host Projects

Internalized all records/classes/interfaces in these host projects except `Program` entry points required for ASP.NET integration hosting:

- `src/Foxlin.Aegir.Api/Models/*`
- `src/Foxlin.Aegir.Api/Services/*`
- `src/Foxlin.Aegir.Web/Models/*`
- `src/Foxlin.Aegir.Web/Pages/*`
- `src/Foxlin.Aegir.Web/Services/*`
- `src/Foxlin.Aegir.App/Models/*`
- `src/Foxlin.Aegir.App/Services/*`
- `src/Foxlin.Aegir.Mcp/Program.cs` request/response records

Specific examples:

- API DTOs: `AccountSummaryDto`, `AdminGroupDto`, `AdminGrantLicenseRequestDto`, `AdminLicenseActionResultDto`, `AdminLicenseSummaryDto`, `AdminRevenueSummaryDto`, `AdminUserModerationRequestDto`, `AdminUserSummaryDto`, `AssignAdminRoleRequestDto`, `AssignFoxlinDeveloperKeyRequestDto`, `AuthHandoffSessionDto`, `AuthHandoffProviderChoiceRequestDto`, `AuthHandoffQrResolutionDto`, `AuthHandoffReturnResultDto`, `CancelAuthHandoffRequestDto`, `CompleteAuthHandoffRequestDto`, `CompleteFederationSessionRequest`, `CreateAdminGroupRequestDto`, `CreateAuthHandoffRequestDto`, `CreateDeveloperAssignmentRequestDto`, `DeveloperApplicationDto`, `DeveloperAssignmentDto`, `DeveloperDashboardDto`, `DeveloperKeyDto`, `DeveloperUsageSummaryDto`, `DistributionTargetDto`, `FederationProviderDto`, `FederationSessionDto`, `GroupMembershipCheckDto`, `IssueDeveloperKeyRequestDto`, `PaymentOptionDto`, `RegisterDeveloperApplicationRequestDto`, `ReportCompromisedDeveloperKeyRequestDto`, `RotateDeveloperKeyRequestDto`, `StartFederationSessionRequest`.
- API runtime services: `AegirAdminRuntimeWorkspace`, `AegirSecurityRuntimeWorkspace`, `AegirAccountRuntimeDirectory`, `AegirDeveloperRuntimeWorkspace`, `AuthHandoffReturnResultFactory`, `AuthHandoffSessionStore`, `FederationSessionStore`.
- Web page models and view models: `AdminModel`, `AdminLoginModel`, `AuthReturnModel`, `DashboardModel`, `DeveloperModel`, `DeveloperCheckoutResultModel`, `DeveloperPricingModel`, `ErrorModel`, `IndexModel`, `InformationModel`, `KycModel`, `PrivacyModel`, `ProfileOnboardingModel`, `ProviderChoiceModel`, `SignInModel`, `SignupModel`, `VaultPromptModel`, plus all `Admin*`, `Developer*`, dashboard/profile/provider view models.
- Web services: `AdminPortalService`, `AegirPasswordHasher`, `AegirSessionSignInService`, `AegirWebPrincipalExtensions`, `AuthHandoffRuntimeService`, `AuthReturnPayloadRuntimeService`, `BootstrapAdminCredentialValidator`, `DeveloperPricingCatalog`, `IAegirAuthSessionService`, `IDeveloperCheckoutService`, `IWebCredentialStore`, `LiveAccountAuthService`, `PortalRuntimeService`, `PostgresWebCredentialStore`, `StripeCheckoutOptions`, `StripeDeveloperCheckoutService`, `UserOnboardingRuntimeService`, `WebCredentialRecord`.
- App runtime: `AegirAppPlatform`, `AegirSecureUnlockMethod`, `AegirAppLocalEncryptedRecord`, `AegirAppHandoffSession`, `AegirAppQrResolution`, `AegirAppCompletionContext`, `AegirAppCompletionResult`, `AegirAppAuthRequest`, `AegirAppFlowResult`, `AegirAppLaunchSource`, `AegirAppLaunchEnvelope`, `AegirAppHostSession`, `IAegirAppLocalEncryptedStore`, `IAegirAppSecureUnlockService`, `IAegirAuthHandoffClient`, `InMemoryAegirAppLocalEncryptedStore`, `AegirApiAuthHandoffClient`, `AegirAppRuntimeService`, `AegirAppLaunchContractParser`, platform hosts/controllers/runtimes.
- MCP transport: `McpRequest`, `McpResponse`, `McpError`.

`Program` partial classes may remain public only where ASP.NET integration tests require them.

### Auth Package Services

Internalized or moved behind the current friend-assembly host boundary:

- Runtime/hosting: `AegirAuthenticationDefaults`, `AegirBootstrapAdminOptions`, `AegirClaimTypes`, `AegirDatabaseBootstrapper`, `AegirHeaderAuthenticationExtensions`, `AegirRuntimeBootstrapper`, `FoxlinBootstrapOptions`.
- Admin/policy: `AegirAccessPolicyEvaluator`, `Beta1AdminAuthorizationPolicy`, `IAdminAuthorizationPolicy`, `IAdminRuntimeStore`, `PostgresAdminRuntimeStore`.
- User/account/recovery/application: `AccountRecoveryService`, `AccountRecoveryOptions`, `IAccountRecoveryService`, `IAccountRecoveryTokenGenerator`, `GuidAccountRecoveryTokenGenerator`, `ApplicationRegistrationService`, `IApplicationRegistrationService`, `UserRegistrationService`, `IUserRegistrationService`, `IUserIdGenerator`, `GuidUserIdGenerator`, `IUserProfileStore`, `PostgresUserProfileStore`.
- Developer/commercial: `DeveloperAccountService`, `IDeveloperAccountService`, `IDeveloperAccountIdGenerator`, `GuidDeveloperAccountIdGenerator`, `DevKeyService`, `IDevKeyService`, `IDevKeyIdGenerator`, `IDevKeySecretGenerator`, `GuidDevKeyIdGenerator`, `GuidDevKeySecretGenerator`, `DevKeySecretHasher`, `DeveloperKeyAuthenticationHandler`, `FoxlinDeveloperAssignmentService`, `IDeveloperCommercialStore`, `PostgresDeveloperCommercialStore`.
- Device/native: `DeviceBootstrapService`, `IDeviceBootstrapService`, `DeviceManagementService`, `IDeviceManagementService`, `SecondaryDeviceEnrollmentService`, `ISecondaryDeviceEnrollmentService`, `ISecondaryDeviceEnrollmentIdGenerator`, `GuidSecondaryDeviceEnrollmentIdGenerator`, `INativeDeviceOperations`, `NativeDeviceOperations`, `NativeDeviceBridge`.
- KYC/research/policy: `Beta1KycIdentityService`, `IKycIdentityService`, `IKycIdentityStore`, `PostgresKycIdentityStore`, `Beta1KycRiskEngine`, `IKycRiskEngine`, `IKycVendorMicroserviceClient`, `LocalNodeKycMicroserviceClient`, `IFoxlinResearchService`, `LocalFoxlinResearchMockService`, `Beta1AgeClaimPolicy`, `IAgeClaimPolicy`, `Beta1GeographicSanctionsPolicy`, `IGeographicSanctionsPolicy`, `Beta1GroupHierarchyPolicy`, `IGroupHierarchyPolicy`.
- OIDC/trust-token: `OidcBridgeService`, `IOidcBridgeService`, `OidcTokenMapper`, `IOidcTokenMapper`, `IOidcCodeStore`, `IOidcCodeGenerator`, `GuidOidcCodeGenerator`, `InMemoryOidcCodeStore`, `TrustTokenIssuer`, `ITrustTokenIssuer`, `TrustTokenIssuerOptions`, `TrustTokenValidator`, `ITrustTokenValidator`, `TrustTokenAuthorizationService`, `ITrustTokenAuthorizationService`, `TrustTokenAuthenticationHandler`, `TrustTokenCodec`.
- Proof ledger/audit/events: `AuditEventRecorder`, `IAuditEventRecorder`, `AuditEventProofBridge`, `IAuditEventProofBridge`, `IAuditEventEntropyProvider`, `GuidAuditEventEntropyProvider`, `IProofBatchBuilder`, `ProofBatchBuilder`, `IProofLedgerCoordinator`, `ProofLedgerCoordinator`, `IProofLedgerExporter`, `ProofLedgerExporter`, `IProofLedgerStore`, `InMemoryProofLedgerStore`, `PostgresProofLedgerStore`, `ProofLedgerRuntime`, `ProofLedgerRuntimeFactory`, `IPhase1EventPublisher`, `IPhase1EventListener`, `InMemoryPhase1EventPublisher`, `InMemoryPhase1EventListener`, `NullPhase1EventPublisher`.
- Persistence/storage: `IRelationalCommandExecutor`, `PostgresRelationalCommandExecutor`, `IRedisKeyValueStore`, `RedisHotPathSecurityState`, `IHotPathSecurityState`, `InMemoryHotPathSecurityState`, `IStoragePolicy`, `Phase1StoragePolicy`, `StoragePolicyOptions`, `StorageKeyConventions`, `ILocalEncryptedStorePolicy`, `Beta1LocalEncryptedStorePolicy`, `ILocalEncryptedStoreContractStore`, `PostgresLocalEncryptedStoreContractStore`, `PostgresOrganizationRuntimeStore`, `IOrganizationRuntimeStore`, `PostgresTrustRecordStore`, `ITrustRecordStore`, `InMemoryTrustRecordStore`.
- Validation/runtime internals: `ChallengeIssuer`, `IChallengeIssuer`, `ChallengeIssuerOptions`, `ChallengeResponseVerifier`, `IChallengeResponseVerifier`, `IRevocationEvaluator`, `RevocationEvaluator`, `IOperationalControlPolicy`, `InMemoryOperationalControlPolicy`, `INonceReplayProtector`, `InMemoryNonceReplayProtector`, `ISupplementalSignalVerifier`, `NoOpSupplementalSignalVerifier`, `PuzzleSupplementalSignalVerifier`, `IPuzzleSignalResolver`, `NativePuzzleSignalResolver`, `Phase1ManifestValidator`, `Beta1VerificationScheduler`, `IVerificationScheduler`.
- Serialization internals: `AegirAuthJsonSerializerContext`, `IdentityGraphSerializer`, `IIdentityGraphSerializer`, `SecurityEventSerializer`, `ISecurityEventSerializer`, `ISecurityEventWriter`, `InMemorySecurityEventWriter`, `PostgresSecurityEventWriter`.
- Crypto/native internals not exposed as portable static SDK helpers: `ITrustCoreInterop`, `NativeTrustCoreInterop`, `NativeTrustCoreBridge`, `ITrustCoreChallengeSigner`, `TrustCoreChallengeSigner`, `ITrustCoreDeviceBinder`, `TrustCoreDeviceBinder`, `ITrustCoreProofReceiptSigner`, `TrustCoreProofReceiptSigner`, `IProofReceiptSigner`, `ProofReceiptSigner`, `ProofReceiptSignerOptions`, `IProofReceiptVerifier`, `ProofReceiptVerifier`, `TrustCoreProofReceiptVerifier`, `ISignatureVerifier`, `ITrustBindingValidator`, `TrustCoreAlgorithmCatalog`.

### Auth Package Models To Remove From SDK Public Surface

Internalized all `Foxlin.Aegir.Auth.Models` records/enums except the keep-public model list above. This includes:

- Admin/access records and enums: `AdminAuthorizationRecord`, `AdminAuthorizationStatus`, `AdminRoleType`, `AdminScopeType`, `AdminUserModerationRecord`, `AegirAccessDecision`, `AegirAccessGrant`, `AegirAccessLevel`, `AegirAccessScope`.
- Account/user/application records: `AccountRecoveryRecord`, `ApplicationRecord`, `ApplicationRegistrationRequest`, `UserRecord`, `UserIdentityRecord`, `UserProfileRecord`, `UserRegistrationRequest`, `UserSelectiveSharingPolicy`.
- Audit/event records: `AuditEventRecord`, `AuditEventOutcome`, `CanonicalSecurityEvent`, `Phase1PlatformEvent`, `Phase1Manifest`, `Phase1ProductIdentity`, `Phase1EventHookDeclaration`, `Phase1StorageDeclaration`, `Phase1OperationalControlsDeclaration`, `Phase1PackageVersions`.
- Billing/developer/commercial records and enums: `BillingAuthorityDelegationRecord`, `BillingAuthorityDelegationStatus`, `BillingCycleRecord`, `BillingCycleStatus`, `BillingPaymentMethodState`, `BillingPaymentMethodType`, `BillingProfileRecord`, `BillingSuspensionState`, `CommercialOwnerType`, `DeveloperAccountRecord`, `DeveloperAccountRegistrationRequest`, `DeveloperEntitlementRecord`, `DeveloperEntitlementStatus`, `DeveloperMembershipRecord`, `DeveloperMembershipRole`, `DeveloperMembershipStatus`, `DeveloperPlanBillingMode`, `DeveloperPlanRecord`, `DevKeyIssueRequest`, `DevKeyIssueResult`, `DevKeyRecord`, `InvoiceProjectionRecord`, `UsageLedgerRecord`, `UsageTransactionType`.
- Device/native records: `CameraAuthenticityAssessment`, `CameraMetadataRecord`, `DeviceBootstrapRequest`, `DeviceFingerprintRecord`, `DeviceIdentityRecord`, `DeviceIntelligenceRecord`, `DeviceKeyRegistrationRequest`, `DeviceKeyRegistrationResult`, `DeviceRecord`, `SecondaryDeviceEnrollmentRecord`, `SecondaryDeviceEnrollmentRequest`.
- KYC/research/age/family/group/geographic records and enums: `AgeBandFlags`, `AgeClaimRecord`, `AgeClaimStatus`, `AgeClaimType`, `EmailIntelligenceRecord`, `EmailVerificationRecord`, `EncryptedDateOfBirthBlock`, `FoxlinResearch*`, `GeographicSanctions*`, `GroupMembershipRecord`, `GroupMembershipStatus`, `GroupStatus`, `IdentityTrustLevel`, `IpIntelligenceRecord`, `Kyc*`, `MaintainedKeyAssignmentRecord`, `MaintainedKeyAssignmentStatus`, `NormalizedKycResult`, `OrganizationGroupRecord`, `OrganizationRecord`, `OrganizationStatus`, `ParentalConsentRecord`, `ParentalConsentStatus`, `ParentalConsentType`, `ParentChildRelationshipRecord`, `ParentChildRelationshipStatus`, `ReverificationIntensity`, `VerificationScheduleRecord`.
- OIDC/trust-token/challenge/revocation/proof-ledger records: `ChallengeContext`, `ChallengeRequest`, `ChallengeSigningRequest`, `ChallengeSigningResult`, `ChallengeVerificationResult`, `ChallengeVerificationStatus`, `IdentityNetworkTokenRecord`, `IssuedChallenge`, `LocalEncryptedStoreContract`, `OidcAuthorizationRequest`, `OidcAuthorizationResponse`, `OidcTokenRequest`, `OidcTokenResponse`, `OidcUserInfo`, `ProofLedgerBatch`, `ProofLedgerExportBundle`, `ProofLedgerReceipt`, `ProofLedgerReceiptVerificationResult`, `ProofLedgerSealResult`, `RevocationEntry`, `RevocationScope`, `SignedChallengeResponse`, `TrustCoreChallengeSignRequest`, `TrustCoreChallengeSignResult`, `TrustCoreDeviceBindingRequest`, `TrustCoreDeviceBindingResult`, `TrustCoreIdentityTokenSignRequest`, `TrustCoreIdentityTokenSignResult`, `TrustCoreProofReceiptSignRequest`, `TrustCoreProofReceiptSignResult`, `TrustCoreProtectionMode`, `TrustToken`, `TrustTokenValidationResult`, `TrustTokenValidationStatus`.

## APIs Needing Renaming Or Consolidation

- C# `BudgetExhaustedException` vs SDK `BudgetExhaustedError`: accepted as ecosystem-specific exception/error naming.
- `AegirRuntimeBootstrapper`, `AegirDatabaseBootstrapper`, and auth header extension methods: either internalize or move to a dedicated hosting package/namespace.

## DTOs/Enums/Models Added To SDKs

Completed for parity with the C# typed public DTOs/enums:

- Java typed models/accessors for:
  - `IdentityGraphNode`
  - `IdentityGraphEdge`
  - `IdentityGraphScores`
  - `ExposureFinding`
  - full `IdentityGraphSnapshot`
  - full `ExposureSummary`
  - full `IdentityActionRecord`
- Java/Python/Go/TypeScript typed or documented equivalents for:
  - `IdentityActionType`
  - `IdentityActionStatus`
  - `IdentityGraphNodeType`
  - `IdentityGraphEdgeType`
  - `ExposureFindingCategory`
  - `ExposureFindingSeverity`
  - `AegirErrorCode`
- Python/Java/Go/C# `BudgetEnvelopeOptions` equivalents are part of the finalized parity surface.

## Finalization Verdict

The intended Beta 1 public surface is defined, and the C# public type surface has been reduced to the compact SDK contract plus ASP.NET `Program` entry points for host testability.

`Public API surface finalized` can be checked for Batch 2C-Fix. Cross-language binding parity is completed by Batch 3D.

## Deprecated: portable trust-core helpers

The six old challenge, proof-receipt and identity-token sign/verify symbols remain to preserve
source linkage, with an intentional security behavior break: signing always throws (Go panics)
and verification always rejects. The homegrown keyless digest has been removed. The supported
local integrity utility is SHA-256 `computePayloadDigest` / `compute_payload_digest` /
`ComputePayloadDigest`; it never establishes identity. Every portable signature envelope is
rejected. Matching unsigned envelope hashes return `integrity_only` and false authentication.

See [the RC1 cryptographic compatibility contract](cryptographic-contracts-rc1.md) for the
per-language mapping and the distinction from genuine runtime keyed cryptography.


## C1 Skills source addendum

See [Skills HTTP MCP source contract](skills-mcp-source.md). The unreleased .NET integration source adds `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`; JavaScript/TypeScript, Python, Java and Go expose this C1 capability only through the raw HTTP contract, without typed C1 methods or claimed C1 native parity. It requires a newly consented `ags1_` reference and current Agent identity. Old no-Skill grants cannot execute Skills. Runtime HTTP registry:14 before filtering; SDK stdio registry:12 with no Skill runner. This source-only addition changes no SDK package version and authorizes no publication or deployment. Runtime qualification is recorded by exact source-bound acceptance receipts; deployment remains unaccepted.


## C2 installed Skills source addendum

The additive [Skills source contract](skills-mcp-source.md#c2-scoped-installation-and-installed-grants) models current Human installation management and separately consented installed grants. The .NET source explicitly selects `AegirSkillMcpClient.ForInstalledSkill` for new `ags2_` references; the default constructor retains C1 `ags1_` mode. All five ecosystems may use the raw installation HTTP contract; no typed management SDK or installed-Skill parity in the other four languages is claimed. Uninstall is terminal for that instance. Explicit reinstall creates a fresh identity and requires fresh execution consent. Package versions and publication status remain unchanged.


## C4 source-only authorization observation

`POST /v1/skills/v2/authorization-inspection` uses the [strict C4 source contract](authorization-skill-source.md) and exact current `ags2_` authority, original Human target and permission. .NET adds a source-only typed API client; Node/TypeScript, Python, Java and Go have raw HTTP only. No new MCP/stdio operation or distribution version. Implementation remains under source-bound qualification; no publication or deployment acceptance.


## C6 source-only Agent enrollment preparation

The [C6 source contract](agent-onboarding-skill-source.md) adds `POST /v1/skills/v2/agent-onboarding-preparation`, operation `application.agent-onboarding.prepare`, in original family `agent-onboarding`. .NET integration source provides `AegirAgentOnboardingSkillApiClient.PrepareAsync` and `ReconcileAsync`. Node/TypeScript, Python, Java and Go have the raw HTTP contract only; no typed C6 parity is claimed. Existing SDK package versions, twelve stdio tools and publication status are unchanged.

This is exact current installed-Skill/consent-bound preparation, not proposal creation, identity registration, issuance approval, credential activation, private-key custody, group membership or delegation. Existing identities cannot be adopted; unsupported prerequisites remain explicit. Full native adversarial qualification is pending; source-bound C6 receipts govern acceptance. No publication, deployment or production release is authorized.


## C7 source-only secure execution and receipt

The [C7 source contract](secure-execution-receipt-skill-source.md) adds `POST /v1/skills/v2/secure-execution` for the bounded canonical group administrative metadata read. .NET integration source offers `AegirSecureExecutionSkillApiClient.ExecuteAsync` / `ReconcileAsync` and `AegirSecureExecutionReceiptVerifier`; Node/TypeScript, Python, Java and Go use raw HTTP only. This source profile adds no MCP/stdio tool, package version or registry publication.

The ML-DSA-65 artifact binds a committed read to its exact original operation and approved authority context. Public verification requires a separately trusted public key, lifecycle facts and operation/tenant/Agent/root/grant/resource context. It proves artifact cryptography under those assumptions; current authority, independent SQL truth, client delivery and external effects require separate evidence. Exact C7 source-bound runtime/review receipts govern acceptance. Production verifier distribution remains unqualified.
