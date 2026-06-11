# MCP Server

The Beta-1 MCP package is a local stdio wrapper around the public Aegir SDK surface.

It is included for developers who want an MCP-compatible tool process on their own machine or inside their own application environment. It is not a hosted service and it does not include deployment automation.

## Boundary

This repository contains:

- local stdio MCP entrypoint: `mcp/src/server.mjs`
- MCP tool-contract tests
- SDK client wiring for the public `/v1/security/*` API surface

This repository does not contain:

- hosted MCP deployment scripts
- systemd service files
- reverse-proxy configuration
- Foxlin production runtime credentials
- private admin/operator routes
- private host/runtime deployment logic

Hosted MCP and production deployment belong outside this SDK tree.

## Required Configuration

The local MCP process reads:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

## Tools

The Beta-1 MCP server exposes only the public Aegir SDK operations:

- `scan_identity`
- `get_identity_graph`
- `get_identity_graph_json`
- `get_exposure_summary`
- `perform_action`
- `reverse_action`
- `get_action_history`

## Local stdio Configuration Example

```json
{
  "command": "node",
  "args": ["C:/path/to/Aegir/mcp/src/server.mjs"],
  "env": {
    "AEGIR_BASE_URL": "https://api.aegir.foxlinindustries.com/apis",
    "AEGIR_CONFIG_KEY": "set-me",
    "AEGIR_DEVELOPER_KEY": "set-me"
  }
}
```

## Expected Failure Modes

In Beta-1, plan for:

- missing or invalid environment configuration
- network or transport failure reaching the hosted Aegir API
- API-side rejections returned through canonical Aegir error semantics
- invalid tool name or malformed JSON-RPC request body

Do not log raw credentials or forward secrets in error output.
