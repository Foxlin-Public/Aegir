# Integration: Python

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
- trust-core signing and verification helpers
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
