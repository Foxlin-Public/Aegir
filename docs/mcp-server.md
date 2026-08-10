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
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is retired and must not be set. The API no longer accepts it as a credential, and it still opens pre-authentication routes - holding it in a client process is exposure with no benefit.

## Tools

Twelve tools, in two groups.

**Identity security**

- `scan_identity`
- `get_identity_graph`
- `get_identity_graph_json`
- `get_exposure_summary`
- `perform_action`
- `reverse_action`
- `get_action_history`

**Transactions and audit**

- `open_transaction` - open a canonical transaction before a protected operation
- `get_transaction` - status and authorization decision
- `get_transaction_events` - the hash-chained event history
- `get_transaction_receipt` - an ML-DSA-65 signed receipt
- `verify_transaction_receipt` - verify one, including whether its key was valid when it signed

## Scopes

The server requests exactly what its tools need:

```
security:read security:write transaction:read transaction:write
```

It deliberately does **not** request `identity:resolve`, `protected:decrypt`, `admin:full` or
`developer:write`. Transaction authority here is audit authority: it proves what Aegir decided
and did, and confers no ability to resolve an opaque principal to a person or to decrypt
anything. Those are separate scopes, and holding audit access never grants them.

On start-up the server exchanges the developer key for a token narrowed to that set, so the
long-lived key is presented once rather than on every call.

## Trust Boundary

This is a **stdio** server. Its transport carries no caller identity, so anything able to talk to
the process acts with the authority of the developer key in its environment. That is the normal
shape for a locally launched MCP server, but it means the process boundary - not the protocol -
is the security boundary. Do not expose it over a network transport without adding per-caller
authentication.

Authorization itself is never decided here. Every tool call goes to the Aegir API, which enforces
scope, tenancy and claim binding server-side. This server duplicates none of those rules.

## Local stdio Configuration Example

```json
{
  "command": "node",
  "args": ["C:/path/to/Aegir/mcp/src/server.mjs"],
  "env": {
    "AEGIR_BASE_URL": "https://api.aegir.foxlinindustries.com/apis",
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
