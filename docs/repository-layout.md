# Repository Layout

## Root

- `README.md`: repo entry point
- `CHANGELOG.md`: Beta-1 SDK release notes for this repo
- `CONTRIBUTING.md`: contribution rules
- `sdk-manifest.json`: version and package manifest

Deployment workflows, hosted MCP service definitions, and runtime infrastructure are intentionally outside this repository.

## `packages`

- `packages/dotnet`: .NET package-facing materials and example
- `packages/npm`: Node/TypeScript Beta-1 package source
- `packages/java`: Java Beta-1 package source
- `packages/python`: Python Beta-1 package source
- `packages/go`: Go Beta-1 package source

## `examples`

- `examples/dotnet`: .NET sample consumer
- `examples/npm`: Node sample consumer

## `installers`

- `install-sdk.ps1`: wrapped PowerShell installer
- `install-sdk.sh`: wrapped shell installer

## `mcp`

- `package.json`: MCP package metadata
- `src/server.mjs`: local Beta-1 stdio MCP server
- `tests/server.test.mjs`: MCP tool-contract tests

Hosted MCP deployment code belongs in a separate deployment/runtime repository, not in the public SDK tree.
