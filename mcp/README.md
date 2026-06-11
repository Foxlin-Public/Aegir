# Aegir SDK MCP

This is the local Beta-1 stdio MCP server for Aegir Security.

It exposes the public Aegir SDK operations to MCP-compatible tools that spawn a local process.

Hosted MCP deployment, reverse-proxy configuration, systemd units, and Foxlin-managed runtime operations are not part of this repository. Those live with the private deployment/runtime repositories.

Configuration:

- `AEGIR_BASE_URL`
- `AEGIR_CONFIG_KEY`
- `AEGIR_DEVELOPER_KEY`

Commands:

- local stdio: `npm start`
