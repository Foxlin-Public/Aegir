# Deployment Boundary

This repository is the public SDK distribution tree. It contains language packages, package-facing documentation, examples, local validation scripts, and the local stdio MCP wrapper.

It is not the Aegir product runtime and it is not a deployment repository.

## Belongs In This Repository

- Public SDK packages for .NET, npm, Maven, PyPI, and Go.
- Public integration docs and quickstarts.
- Public model, error, diagnostics, budget, safe-envelope, and A2A contracts.
- Local examples that call the hosted public Aegir API surface.
- Local stdio MCP wrapper over the same public SDK operations.
- Package validation and local developer bootstrap helpers.

## Does Not Belong In This Repository

- Foxlin production deployment scripts.
- Hosted MCP deployment scripts or systemd units.
- Kubernetes, VPS, reverse-proxy, cloud, or secret-management configuration.
- Product host/runtime source code.
- Admin, billing, KYC, OIDC, proof-ledger, storage, persistence, recovery, organization, or trust-token runtime internals.
- Operator-only documentation or credentials.

## Public Repository Shape

The intended public repository layout is:

```text
Foxlin-Public/Aegir
  Aegir/
    docs/
    examples/
    installers/
    mcp/
    packages/
    sdk-manifest.json
```

Deployment and runtime repositories remain separate private Foxlin repositories.
