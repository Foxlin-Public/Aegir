# Integration: Python

> **RC1 source update — AEG-RC1-R004:** portable `sign*Payload` compatibility stubs now
> throw (Go panics); `verify*Payload` always rejects. Local envelopes validate integrity only,
> report `isAuthenticated=false`, and reject every non-null signature envelope. Standard SHA-256
> is exposed as `computePayloadDigest` (`compute_payload_digest`, `ComputePayloadDigest`).
> See [the cryptographic compatibility contract](cryptographic-contracts-rc1.md).
> This is unreleased source behavior, not a registry publication.


## Package

- package: `foxlin-aegir-security`
- version: `0.1.1-beta.1`

## What The Python SDK Covers

Use the Python SDK when you want hosted Aegir Beta-1 access from automation, data-processing jobs, scripting, or service integrations.

The Beta-1 Python package includes:

- `AegirSecurityClient`
- safe envelopes
- budget envelopes
- in-memory agent-to-agent helpers
- deprecated fail-closed trust-core compatibility stubs
- diagnostics hooks
- canonical error semantics

## Required Configuration

The Python client needs:

- `AEGIR_BASE_URL`
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is retired and must not be set. The API no longer accepts it as a credential, and it still opens pre-authentication routes - holding it in a client process is exposure with no benefit.

## Beta-1 Operations

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

```python
client = AegirSecurityClient(
    base_url=os.environ["AEGIR_BASE_URL"],
    developer_key=os.environ["AEGIR_DEVELOPER_KEY"],
)

# Narrow to what you need. The token expires; the developer key does not.
client.useNarrowedToken("security:read transaction:read")
```

Also: `getToken`, `introspectToken`, `revokeToken`, `useAgentKey`.

### Agents

```python
agent = client.registerAgent("triage-bot", scopes=["agent:invoke", "transaction:write"])
# agent["agentKey"] is returned once and never again.
```

Also: `listAgents`, `revokeAgent`, `bindProvider`.

### Transactions

Open the transaction **before** the protected operation, so a refusal is recorded as fully as a
success.

```python
tx = client.createTransaction("ai.provider.invoke")
events = client.getTransactionEvents(tx["transactionId"])
receipt = client.getTransactionReceipt(tx["transactionId"])
check = client.verifyTransactionReceipt(receipt)   # {"valid": True, "status": "Valid"}
```

A receipt carries hashes and decisions - never payloads or personal identity - and is signed
ML-DSA-65, so it still verifies after the signing key is retired.

### Protected AI operations

```python
agent_client = AegirSecurityClient(base_url=os.environ["AEGIR_BASE_URL"])
agent_client.useAgentKey(agent["agentKey"])

tx = agent_client.createTransaction("agent.message.send")

message = agent_client.sendAgentMessage(
    tx["transactionId"],
    other_agent_id,
    "agent.finding.share",
    base64.b64encode(json.dumps(finding).encode()).decode(),
)

# Relay `message` unchanged. Every field is authenticated; an edit fails validation.
delivery = recipient_client.receiveAgentMessage(message)
```

`invokeProvider` calls OpenAI or Anthropic through Aegir as the authenticated agent. A vendor
failure comes back as `succeeded: False` with a normalized `errorKind` rather than raising.

## Integration Notes

For Beta-1, the Python package is designed to stay close to the hosted Aegir API surface. That makes it easier to move between SDK and MCP usage without learning a second product model.

## Example Pattern

The expected Python flow is:

1. initialize `AegirSecurityClient`
2. call one of the hosted Beta-1 operations
3. inspect the returned object or JSON payload
4. handle canonical Aegir client errors in your automation or service logs

## Beta-1 Boundary

The Python package exposes the hosted/public Beta-1 surface only.


## C1 Skills source addendum

See [Skills HTTP MCP source contract](skills-mcp-source.md). The unreleased .NET integration source adds `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`; JavaScript/TypeScript, Python, Java and Go expose this C1 capability only through the raw HTTP contract, without typed C1 methods or claimed C1 native parity. It requires a newly consented `ags1_` reference and current Agent identity. Old no-Skill grants cannot execute Skills. Runtime HTTP registry:14 before filtering; SDK stdio registry:12 with no Skill runner. This source-only addition changes no SDK package version and authorizes no publication or deployment. Runtime qualification is recorded by exact source-bound acceptance receipts; deployment remains unaccepted.


## C2 installed Skills source addendum

The additive [Skills source contract](skills-mcp-source.md#c2-scoped-installation-and-installed-grants) models current Human installation management and separately consented installed grants. The .NET source explicitly selects `AegirSkillMcpClient.ForInstalledSkill` for new `ags2_` references; the default constructor retains C1 `ags1_` mode. All five ecosystems may use the raw installation HTTP contract; no typed management SDK or installed-Skill parity in the other four languages is claimed. Uninstall is terminal for that instance. Explicit reinstall creates a fresh identity and requires fresh execution consent. Package versions and publication status remain unchanged.


## C3 authentication inspection source addendum

The separate [authentication Skill API contract](authentication-skill-source.md) inspects only actual executing-API-host application configuration prerequisites under current exact group/app/installed authority. This language has the raw HTTP contract only; no typed authentication-Skill API or claimed C3 runtime parity. Existing metadata MCP bindings remain audit-only. No Human authentication, secret export, new MCP/stdio tool, package version change, publication or deployment. C3 implementation/acceptance receipts govern qualification.

C3 recovery integrity: after the exact authentication Skill version is first declared, supported PostgreSQL application create/save operations validate and advance the existing independent consent journal before SQL commit. Its fixed fingerprint covers application ID, developer, environment, status and UTC creation identity; it grants no permissions. Missing, mismatched or interrupted independent truth refuses with unavailable/unknown-reconcile semantics. Unconfigured imports or externally owned enrolled write transactions fail closed. No automatic witness repair or legacy approval is provided. The fingerprint is computed from bounded pages of fixed row digests while existing canonical admission fences application mutations; total scan/sort work still grows with retained applications. This is not a global creation quota, production-scale claim or universal rollback detector for developer/group/license/policy tables.


## C4 authorization inspection source addendum

See [the bounded RBAC Skill source contract](authorization-skill-source.md). This ecosystem uses the raw HTTP contract only; no new typed authorization-Skill API or runtime parity is claimed. Current independent inspection authority is distinct from the observed business decision. The original consenting Human is the only target; observations grant no future access. Preserve exact operation identity and reconcile uncertain outcomes explicitly. No role/membership/credential mutation, new MCP tool, package version bump, publication or deployment. C4 final source-bound receipts govern qualification.
