# Aegir SDK

This is the standalone Beta-1 SDK repository for Aegir Security.

Aegir is Foxlin Industries' identity, authentication and authorization engine. It issues scoped, expiring access tokens; gives an AI agent a first-class identity of its own, distinct from the developer key that manages it; records security operations as hash-chained transactions; and returns ML-DSA-65 signed receipts that verify independently of the service that issued them. Applications call it to answer who a caller is, what they may do, and what they did.

This repository is for developers integrating against the public Beta-1 Aegir SDK surface. It does not include deployment automation, private product runtime code, internal admin code, or Beta-2 features.

## Who This Is For

Use this repo if you are:

- integrating Aegir into an external application or service
- building automation that needs the hosted public Aegir API
- testing the local Beta-1 MCP stdio wrapper
- evaluating the Beta-1 SDK surface across `.NET`, `Node`, or `Python`

## What To Use Today

The Beta-1 release covers three SDKs:

| Language | Package | Version |
|---|---|---|
| .NET | `Foxlin.Aegir.Security` | `0.1.1-beta.1` |
| Node | `@foxlin_industries/aegir-security` | `0.1.1-beta.1` |
| Python | `foxlin-aegir-security` | `0.1.1-beta.1` (installs as `0.1.1b1`, per PEP 440) |

**Java and Go are not part of Beta-1.** Their source lives in
[packages/java](./packages/java) and [packages/go](./packages/go) so it can be read and built
locally, but neither is published to a package registry and neither should be depended on in
production. `cloud.foxlin:aegir-security` is not on Maven Central, and the Go module path has no
domain, so `go get` cannot resolve it.

The Beta-1 MCP wrapper is in [mcp](./mcp) and supports:

- local `stdio` transport for MCP-compatible tools

Hosted MCP deployment and production runtime operations are intentionally outside this repository.

## Beta-1 Surface

Beta-1 groups its operations into five areas. Names below are the Node/Python form; .NET
groups the same operations under `client.Tokens`, `client.Agents`, `client.Transactions` and
`client.Ai`.

**Authentication and tokens**
`getToken`, `useNarrowedToken`, `useAgentKey`, `introspectToken`, `revokeToken`

Prefer a narrowed token over presenting a developer key on every request: it carries only the
scopes you asked for, and it expires.

**AI agent identity**
`registerAgent`, `listAgents`, `revokeAgent`, `bindProvider`

An agent is a principal in its own right, distinct from the developer key that manages it. It has
its own credential, its own scopes and its own revocation. An agent can never register another
agent or widen its own authority.

**Transactions and receipts**
`createTransaction`, `getTransaction`, `getTransactionEvents`, `getTransactionReceipt`,
`verifyTransactionReceipt`

Open a transaction *before* the protected operation. That ordering is the point: a denied or
abandoned attempt is as auditable as a successful one. Events form a hash chain, and receipts are
ML-DSA-65 signed and independently verifiable.

**Protected AI operations**
`listProviders`, `invokeProvider`, `sendAgentMessage`, `receiveAgentMessage`

Invoke OpenAI or Anthropic through Aegir as an authenticated agent, or send a payload to another
agent protected end to end with ML-KEM-768 key establishment, AES-256-GCM encryption and an
ML-DSA-65 signature. A protected message is bound to its transaction and is not transferable to
another one.

**Identity security**
`scanIdentity`, `getIdentityGraph`, `getIdentityGraphJson`, `getExposureSummary`,
`performAction`, `reverseAction`, `getActionHistory`

Also included: diagnostics hooks, canonical error semantics and budget envelopes.

## Authentication Model

Beta-1 access is environment-based and API-backed. SDK and local MCP integrations use two
variables:

- `AEGIR_BASE_URL`
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is **no longer used and must not be set**. The API stopped accepting it as a
credential on identity-bearing routes, and it still opens pre-authentication routes, so holding it
in a client process is exposure with no benefit.

Two principal types can authenticate:

- a **developer key**, which manages applications and agents, and
- an **agent key**, which acts. Exchange it with `useAgentKey`; the resulting token names the
  agent as the acting principal, and every agent-scoped operation reads that identity from the
  token rather than from a request body.

## Typical Request Lifecycle

For an identity-security integration:

1. configure the SDK with the Aegir base URL and your developer key
2. narrow to a scoped token with `useNarrowedToken`
3. call an operation such as `scanIdentity` or `performAction`
4. receive a typed response or a canonical error payload

For a protected AI operation, the shape is different, and the ordering matters:

1. authenticate as an agent with `useAgentKey`
2. **open a transaction** with `createTransaction`
3. perform the protected operation - `invokeProvider` or `sendAgentMessage` - naming that
   transaction
4. read `getTransactionEvents` for the decision trail, or `getTransactionReceipt` for a signed,
   independently verifiable record

Step 2 is not bookkeeping. The transaction exists before the operation so that a refusal is
recorded as fully as a success.

The SDK does not require direct access to private Foxlin runtime services. It talks only to the hosted/public Aegir surface defined for Beta-1.

Canonical production hosts:

- application host: `https://aegir.foxlinindustries.com`
- API host: `https://api.aegir.foxlinindustries.com/apis`

## Quick Start

### PowerShell

```powershell
pwsh ./installers/install-sdk.ps1 -Node -DotNet -Mcp
```

### Bash

```bash
bash ./installers/install-sdk.sh --node --dotnet --mcp
```

## Start Here

- [.NET integration guide](./docs/integration-dotnet.md)
- [Node integration guide](./docs/integration-node.md)
- [Python integration guide](./docs/integration-python.md)
- [MCP server guide](./docs/mcp-server.md)

Not released in Beta-1, source-only:

- [Java integration guide](./docs/integration-java.md)
- [Go integration guide](./docs/integration-go.md)

Also useful:

- [Deployment Boundary](./docs/deployment-boundary.md)

## Repo Layout

- [docs](./docs): Beta-1 SDK documentation
- [installers](./installers): wrapped installer scripts
- [packages](./packages): language SDK packages and package-facing materials
- [examples](./examples): small example consumers
- [mcp](./mcp): local Beta-1 stdio MCP wrapper

## Beta-1 Documents

- [Beta-1 Scope](./docs/beta1-scope.md)
- [Repository Layout](./docs/repository-layout.md)
- [Installer Guide](./docs/installer.md)
- [MCP Server Guide](./docs/mcp-server.md)
- [Deployment Boundary](./docs/deployment-boundary.md)
- [Integration: .NET](./docs/integration-dotnet.md)
- [Integration: Node](./docs/integration-node.md)
- [Integration: Java](./docs/integration-java.md)
- [Integration: Python](./docs/integration-python.md)
- [Integration: Go](./docs/integration-go.md)

## What This Repo Does Not Include

This repo does not include:

- private Foxlin product runtime code
- hosted MCP deployment code
- production deployment scripts or infrastructure configuration
- unpublished admin or operator-only capabilities
- Beta-2 features
- release-channel recommendations beyond the current Beta-1 packages and examples in this repo
