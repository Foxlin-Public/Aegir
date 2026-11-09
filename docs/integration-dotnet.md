# Integration: .NET

> **RC1 source update — AEG-RC1-R004:** portable `sign*Payload` compatibility stubs now
> throw (Go panics); `verify*Payload` always rejects. Local envelopes validate integrity only,
> report `isAuthenticated=false`, and reject every non-null signature envelope. Standard SHA-256
> is exposed as `computePayloadDigest` (`compute_payload_digest`, `ComputePayloadDigest`).
> See [the cryptographic compatibility contract](cryptographic-contracts-rc1.md).
> This is unreleased source behavior, not a registry publication.


## Package

- package: `Foxlin.Aegir.Security`
- version: `0.1.1-beta.1`

## What The .NET SDK Covers

Use the `.NET` SDK when you want typed access to the hosted Aegir Beta-1 surface from ASP.NET, worker services, automation jobs, or other `.NET` applications.

The Beta-1 `.NET` package includes:

- the hosted Aegir API client
- typed request and response models
- canonical client error handling
- diagnostics hooks
- trust-core helper utilities
- safe-envelope and budget-envelope helpers
- access-control evaluation helpers

## Required Configuration

The `.NET` client needs:

- `AEGIR_BASE_URL`
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is retired and must not be set. The API no longer accepts it as a credential, and it still opens pre-authentication routes - holding it in a client process is exposure with no benefit.

These values identify the hosted Aegir endpoint and the developer credentials used for Beta-1 access.

## Beta-1 Operations

The public Beta-1 operations are:

- `ScanIdentityAsync`
- `GetIdentityGraphAsync`
- `GetIdentityGraphJsonAsync`
- `GetExposureSummaryAsync`
- `PerformActionAsync`
- `ReverseActionAsync`
- `GetActionHistoryAsync`

## Beta-1 Capabilities

The client groups its operations into four capability properties.

```csharp
var client = new AegirSecurityHttpClient(new AegirSecurityClientOptions
{
    BaseUrl = Environment.GetEnvironmentVariable("AEGIR_BASE_URL")!,
    DeveloperKey = Environment.GetEnvironmentVariable("AEGIR_DEVELOPER_KEY")
});

client.Tokens        // authentication and token lifecycle
client.Agents        // agent identity and provider binding
client.Transactions  // transactions, event history, signed receipts
client.Ai            // provider invocation and protected messaging
```

### Tokens

```csharp
// Narrow to what you need. The token expires; the developer key does not.
await client.Tokens.UseNarrowedTokenAsync("security:read transaction:read");
```

Also: `GetTokenAsync`, `IntrospectAsync`, `RevokeAsync`, `UseAgentKeyAsync`.

### Agents

```csharp
AegirAgentRegistration agent = await client.Agents.RegisterAsync(
    new AegirRegisterAgentRequest("triage-bot", Scopes: ["agent:invoke", "transaction:write"]));
// agent.AgentKey is returned once and never again.
```

Also: `ListAsync`, `RevokeAsync`, `BindProviderAsync`.

### Transactions

Open the transaction **before** the protected operation, so a refusal is recorded as fully as a
success.

```csharp
AegirTransactionSummary tx = await client.Transactions.CreateAsync(
    new AegirCreateTransactionRequest("ai.provider.invoke"));

AegirTransactionReceipt receipt = await client.Transactions.GetReceiptAsync(tx.TransactionId);
AegirReceiptVerification check = await client.Transactions.VerifyReceiptAsync(receipt);
```

A receipt carries hashes and decisions - never payloads or personal identity - and is signed
ML-DSA-65, so it still verifies after the signing key is retired.

### Protected AI operations

```csharp
AegirProtectedMessage message = await agentClient.Ai.SendProtectedMessageAsync(
    new AegirSendProtectedMessageRequest(tx.TransactionId, recipientAgentId,
        "agent.finding.share", base64Payload));

// Relay `message` unchanged. Every field is authenticated; an edit fails validation.
AegirProtectedDelivery delivery = await recipientClient.Ai.ReceiveProtectedMessageAsync(message);
```

Models live in `Foxlin.Aegir.Auth.Client`. A full walkthrough is in
[examples/dotnet](../examples/dotnet).

## Access Control Helpers

The `.NET` package also includes:

- `AegirAccessLevel`
- `AegirAccessScope`
- `AegirAccessGrant`
- `AegirAccessDecision`
- `AegirAccessPolicyEvaluator`

These helpers let you evaluate `read_only`, `partial_control`, and `full_control` access patterns inside your own application without inventing a second access model.

## Typical Request Lifecycle

In a normal Beta-1 flow:

1. initialize the client with the hosted API base URL and your Aegir credentials
2. call one of the Beta-1 operations
3. inspect the typed result
4. handle canonical client exceptions when the request is rejected or malformed
5. optionally record diagnostics or inspect action history

## Error Handling

The `.NET` package uses canonical Aegir client exceptions for API-side failures. In Beta-1, your integration should assume these broad categories:

- configuration failures, such as missing base URL or keys
- transport or network failures
- API rejections with Aegir error metadata
- malformed request payloads from the calling application

Your application should treat Aegir API calls as external service calls:

- validate inputs before sending them
- log the Aegir correlation or diagnostic data you receive
- surface actionable errors to operators without exposing secrets

## Retries

The SDK does not hide the fact that the hosted Aegir API is a remote dependency. For Beta-1:

- retry only idempotent read-style operations when your platform policy allows it
- avoid blind retries for mutation-style operations such as `PerformActionAsync` or `ReverseActionAsync`
- capture diagnostics before retrying so you can distinguish transport issues from rejected requests

## Example

See [../examples/dotnet/Program.cs](../examples/dotnet/Program.cs).

## Beta-1 Boundary

The `.NET` SDK in this repo is limited to the current hosted/public Beta-1 surface. It does not expose Beta-2 operations or private Foxlin runtime features.


## C1 Skills source addendum

See [Skills HTTP MCP source contract](skills-mcp-source.md). The unreleased .NET integration source adds `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`; JavaScript/TypeScript, Python, Java and Go expose this C1 capability only through the raw HTTP contract, without typed C1 methods or claimed C1 native parity. It requires a newly consented `ags1_` reference and current Agent identity. Old no-Skill grants cannot execute Skills. Runtime HTTP registry:14 before filtering; SDK stdio registry:12 with no Skill runner. This source-only addition changes no SDK package version and authorizes no publication or deployment. Runtime qualification is recorded by exact source-bound acceptance receipts; deployment remains unaccepted.


## C2 installed Skills source addendum

The additive [Skills source contract](skills-mcp-source.md#c2-scoped-installation-and-installed-grants) models current Human installation management and separately consented installed grants. The .NET source explicitly selects `AegirSkillMcpClient.ForInstalledSkill` for new `ags2_` references; the default constructor retains C1 `ags1_` mode. All five ecosystems may use the raw installation HTTP contract; no typed management SDK or installed-Skill parity in the other four languages is claimed. Uninstall is terminal for that instance. Explicit reinstall creates a fresh identity and requires fresh execution consent. Package versions and publication status remain unchanged.


## C3 authentication inspection source addendum

The separate [authentication Skill API contract](authentication-skill-source.md) inspects only actual executing-API-host application configuration prerequisites under current exact group/app/installed authority. The .NET source adds `AegirAuthenticationSkillApiClient.InspectAsync` and `ReconcileAsync`; preserve the original operation and expected grant, with no automatic retry. Existing metadata MCP bindings remain audit-only. No Human authentication, secret export, new MCP/stdio tool, package version change, publication or deployment. C3 implementation/acceptance receipts govern qualification.

C3 recovery integrity: after the exact authentication Skill version is first declared, supported PostgreSQL application create/save operations validate and advance the existing independent consent journal before SQL commit. Its fixed fingerprint covers application ID, developer, environment, status and UTC creation identity; it grants no permissions. Missing, mismatched or interrupted independent truth refuses with unavailable/unknown-reconcile semantics. Unconfigured imports or externally owned enrolled write transactions fail closed. No automatic witness repair or legacy approval is provided. The fingerprint is computed from bounded pages of fixed row digests while existing canonical admission fences application mutations; total scan/sort work still grows with retained applications. This is not a global creation quota, production-scale claim or universal rollback detector for developer/group/license/policy tables.


## C4 authorization inspection source addendum

See [the bounded RBAC Skill source contract](authorization-skill-source.md). The .NET source provides `AegirAuthorizationSkillApiClient.InspectAsync` and explicit `ReconcileAsync` with exact target, permission and expected grant. Current independent inspection authority is distinct from the observed business decision. The original consenting Human is the only target; observations grant no future access. Preserve exact operation identity and reconcile uncertain outcomes explicitly. No role/membership/credential mutation, new MCP tool, package version bump, publication or deployment. C4 final source-bound receipts govern qualification.
