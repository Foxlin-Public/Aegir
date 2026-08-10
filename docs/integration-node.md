# Integration: Node

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
- trust-core signing and verification helpers

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
