# Integration: Node

> **RC1 source update — AEG-RC1-R004:** portable `sign*Payload` compatibility stubs now
> throw (Go panics); `verify*Payload` always rejects. Local envelopes validate integrity only,
> report `isAuthenticated=false`, and reject every non-null signature envelope. Standard SHA-256
> is exposed as `computePayloadDigest` (`compute_payload_digest`, `ComputePayloadDigest`).
> See [the cryptographic compatibility contract](cryptographic-contracts-rc1.md).
> This is unreleased source behavior, not a registry publication.


## Package

- package: `@foxlin_industries/aegir-security`
- version: `0.1.1-beta.1`

## What The Node SDK Covers

Use the Node SDK when you want to call the hosted Aegir Beta-1 API from Node services, edge tooling, automation scripts, or MCP-adjacent JavaScript runtimes.

The Beta-1 Node package includes:

- the hosted Aegir client
- canonical error handling
- diagnostics hooks
- safe envelopes
- budget envelopes
- in-memory agent-to-agent helpers
- deprecated fail-closed trust-core compatibility stubs

## Required Configuration

The Node client needs:

- `AEGIR_BASE_URL`
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is retired and must not be set. The API no longer accepts it as a credential, and it still opens pre-authentication routes - holding it in a client process is exposure with no benefit.

These values define the hosted Aegir endpoint and the developer credentials for the integration.

## Beta-1 Operations

The public Beta-1 operations are:

- `scanIdentity`
- `getIdentityGraph`
- `getIdentityGraphJson`
- `getExposureSummary`
- `performAction`
- `reverseAction`
- `getActionHistory`

## Beta-1 Capabilities

Beyond the identity-security operations above, the client exposes four more groups.

### Tokens

```js
const client = new AegirSecurityClient({
  baseUrl: process.env.AEGIR_BASE_URL,
  developerKey: process.env.AEGIR_DEVELOPER_KEY
});

// Narrow to what you need. The token expires; the developer key does not.
await client.useNarrowedToken("security:read transaction:read");
```

Also: `getToken`, `introspectToken`, `revokeToken`, `useAgentKey`.

### Agents

An agent is a principal in its own right, with its own credential, scopes and revocation.

```js
const agent = await client.registerAgent({
  displayName: "triage-bot",
  scopes: ["agent:invoke", "transaction:write"]
});
// agent.agentKey is returned once and never again.
```

Also: `listAgents`, `revokeAgent`, `bindProvider`.

### Transactions

Open the transaction **before** the protected operation, so a refusal is recorded as fully as a
success.

```js
const tx = await client.createTransaction({ declaredAction: "ai.provider.invoke" });
const events = await client.getTransactionEvents(tx.transactionId);
const receipt = await client.getTransactionReceipt(tx.transactionId);
const check = await client.verifyTransactionReceipt(receipt);   // { valid, status }
```

A receipt carries hashes and decisions - never payloads or personal identity - and is signed
ML-DSA-65, so it still verifies after the signing key is retired.

### Protected AI operations

```js
// Authenticate as the agent, then act.
const agentClient = new AegirSecurityClient({ baseUrl: process.env.AEGIR_BASE_URL });
await agentClient.useAgentKey(agent.agentKey);

const tx = await agentClient.createTransaction({ declaredAction: "agent.message.send" });

const message = await agentClient.sendAgentMessage({
  transactionId: tx.transactionId,
  recipientAgentId: otherAgentId,
  action: "agent.finding.share",
  payload: Buffer.from(JSON.stringify(finding)).toString("base64")
});

// Relay `message` unchanged. Every field is authenticated; an edit fails validation.
const delivery = await recipientClient.receiveAgentMessage(message);
```

`invokeProvider` calls OpenAI or Anthropic through Aegir as the authenticated agent. A vendor
failure comes back as `succeeded: false` with a normalized `errorKind` rather than throwing, so a
failed call is recorded exactly like a successful one.

## Typical Request Lifecycle

In a normal Beta-1 Node flow:

1. construct the client with the hosted API base URL and credentials
2. call a read or action operation
3. inspect the returned object
4. catch canonical Aegir client errors and log the provided error code or correlation metadata
5. forward only safe, application-level error messages to callers

## Error Handling

The Node SDK treats the hosted Aegir API as a remote dependency. For Beta-1, your integration should plan for:

- missing or invalid configuration
- network or transport failures
- API-side rejections with canonical Aegir error semantics
- malformed application payloads

Use the canonical error shape consistently in your app logs and monitoring so operators can distinguish Aegir policy rejections from local application bugs.

## Retries

For Beta-1:

- retries are safest on read-oriented operations
- mutation operations should be retried only with clear idempotency rules in your own application
- log the original failure before retrying so you preserve the Aegir error context

## Example

See [../examples/npm/index.mjs](../examples/npm/index.mjs).

## Beta-1 Boundary

The Node package in this repo exposes only the current hosted/public Beta-1 surface. It does not include unpublished Foxlin runtime operations or Beta-2 capabilities.


## C1 Skills source addendum

See [Skills HTTP MCP source contract](skills-mcp-source.md). The unreleased .NET integration source adds `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`; JavaScript/TypeScript, Python, Java and Go expose this C1 capability only through the raw HTTP contract, without typed C1 methods or claimed C1 native parity. It requires a newly consented `ags1_` reference and current Agent identity. Old no-Skill grants cannot execute Skills. Runtime HTTP registry:14 before filtering; SDK stdio registry:12 with no Skill runner. This source-only addition changes no SDK package version and authorizes no publication or deployment. Runtime qualification is recorded by exact source-bound acceptance receipts; deployment remains unaccepted.


## C2 installed Skills source addendum

The additive [Skills source contract](skills-mcp-source.md#c2-scoped-installation-and-installed-grants) models current Human installation management and separately consented installed grants. The .NET source explicitly selects `AegirSkillMcpClient.ForInstalledSkill` for new `ags2_` references; the default constructor retains C1 `ags1_` mode. All five ecosystems may use the raw installation HTTP contract; no typed management SDK or installed-Skill parity in the other four languages is claimed. Uninstall is terminal for that instance. Explicit reinstall creates a fresh identity and requires fresh execution consent. Package versions and publication status remain unchanged.


## C3 authentication inspection source addendum

The separate [authentication Skill API contract](authentication-skill-source.md) inspects only actual executing-API-host application configuration prerequisites under current exact group/app/installed authority. This language has the raw HTTP contract only; no typed authentication-Skill API or claimed C3 runtime parity. Existing metadata MCP bindings remain audit-only. No Human authentication, secret export, new MCP/stdio tool, package version change, publication or deployment. C3 implementation/acceptance receipts govern qualification.

C3 recovery integrity: after the exact authentication Skill version is first declared, supported PostgreSQL application create/save operations validate and advance the existing independent consent journal before SQL commit. Its fixed fingerprint covers application ID, developer, environment, status and UTC creation identity; it grants no permissions. Missing, mismatched or interrupted independent truth refuses with unavailable/unknown-reconcile semantics. Unconfigured imports or externally owned enrolled write transactions fail closed. No automatic witness repair or legacy approval is provided. The fingerprint is computed from bounded pages of fixed row digests while existing canonical admission fences application mutations; total scan/sort work still grows with retained applications. This is not a global creation quota, production-scale claim or universal rollback detector for developer/group/license/policy tables.


## C4 authorization inspection source addendum

See [the bounded RBAC Skill source contract](authorization-skill-source.md). This ecosystem uses the raw HTTP contract only; no new typed authorization-Skill API or runtime parity is claimed. Current independent inspection authority is distinct from the observed business decision. The original consenting Human is the only target; observations grant no future access. Preserve exact operation identity and reconcile uncertain outcomes explicitly. No role/membership/credential mutation, new MCP tool, package version bump, publication or deployment. C4 final source-bound receipts govern qualification.
