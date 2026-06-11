# Aegir SDK

This is the standalone Beta-1 SDK repository for Aegir Security.

Aegir is Foxlin's security platform for identity scanning, graph-aware exposure analysis, controlled security actions, and developer-facing SDK access over the hosted Aegir API surface.

This repository is for developers integrating against the public Beta-1 Aegir SDK surface. It does not include deployment automation, private product runtime code, internal admin code, or Beta-2 features.

## Who This Is For

Use this repo if you are:

- integrating Aegir into an external application or service
- building automation that needs the hosted public Aegir API
- testing the local Beta-1 MCP stdio wrapper
- evaluating the Beta-1 SDK surface across `.NET`, `Node`, `Java`, `Python`, or `Go`

## What To Use Today

The current public Beta-1 packages are:

- `.NET`: `Foxlin.Aegir.Security` version `0.1.1-beta-1`
- `Node`: `@foxlin_industries/aegir-security` version `0.1.1-beta-1`
- `Java`: `cloud.foxlin:aegir-security` version `0.1.1-beta-1`
- `Python`: `foxlin-aegir-security` version `0.1.1-beta-1`
- `Go`: module `foxlin/aegir-security-go`

The Beta-1 MCP wrapper is in [mcp](./mcp) and supports:

- local `stdio` transport for MCP-compatible tools

Hosted MCP deployment and production runtime operations are intentionally outside this repository.

## Beta-1 Surface

The Beta-1 API surface exposed by the SDKs and MCP server is intentionally small and stable:

- `scanIdentity`
- `getIdentityGraph`
- `getIdentityGraphJson`
- `getExposureSummary`
- `performAction`
- `reverseAction`
- `getActionHistory`

Beta-1 package helpers also include:

- safe envelopes
- budget envelopes
- minimal in-memory agent-to-agent protocol
- trust-core signing and verification helpers
- diagnostics hooks
- canonical error semantics
- access control helpers in `.NET`

## Authentication Model

Beta-1 access is environment-based and API-backed.

SDK and local MCP integrations use:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

In Beta-1, the SDK authenticates to the hosted Aegir API with the configured key pair.

## Typical Request Lifecycle

For most Beta-1 integrations, the flow is:

1. configure the SDK or local MCP wrapper with the hosted Aegir base URL and developer credentials
2. submit one of the Beta-1 operations such as `scanIdentity` or `performAction`
3. receive a typed response or canonical error payload
4. inspect diagnostics, envelope helpers, or action history as needed

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
- [Java integration guide](./docs/integration-java.md)
- [Python integration guide](./docs/integration-python.md)
- [Go integration guide](./docs/integration-go.md)
- [MCP server guide](./docs/mcp-server.md)
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
- [Next Pass Public Repo Notes](./docs/public-repo-next-pass.md)

## What This Repo Does Not Include

This repo does not include:

- private Foxlin product runtime code
- hosted MCP deployment code
- production deployment scripts or infrastructure configuration
- unpublished admin or operator-only capabilities
- Beta-2 features
- release-channel recommendations beyond the current Beta-1 packages and examples in this repo
