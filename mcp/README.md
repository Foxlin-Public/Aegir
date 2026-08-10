# Aegir SDK MCP

This is the local Beta-1 stdio MCP server for Aegir Security.

It exposes the public Aegir SDK operations to MCP-compatible tools that spawn a local process.

Hosted MCP deployment, reverse-proxy configuration, systemd units, and Foxlin-managed runtime operations are not part of this repository. Those live with the private deployment/runtime repositories.

Configuration:

- `AEGIR_BASE_URL`
- `AEGIR_DEVELOPER_KEY` - in the form `devKeyId:secret`

`AEGIR_CONFIG_KEY` is retired and must not be set. The API no longer accepts it as a credential, and it still opens pre-authentication routes - holding it in a client process is exposure with no benefit.

Commands:

- local stdio: `npm start`
- tests: `npm test`

## Tools

Identity security: `scan_identity`, `get_identity_graph`, `get_identity_graph_json`,
`get_exposure_summary`, `perform_action`, `reverse_action`, `get_action_history`.

Transactions and audit: `open_transaction`, `get_transaction`, `get_transaction_events`,
`get_transaction_receipt`, `verify_transaction_receipt`.

## Scopes And Boundary

The server narrows its credential to `security:read security:write transaction:read
transaction:write` and asks for nothing wider - notably not `identity:resolve`,
`protected:decrypt` or `admin:full`.

It speaks **stdio**, which carries no caller identity, so whatever can talk to the process acts
with the authority of the developer key in its environment. The process boundary is the security
boundary. Do not put it behind a network transport without adding per-caller authentication.

Authorization is enforced by the Aegir API, not here.

## Distribution

Source-only. This server is not published to npm; run it from this repository.
