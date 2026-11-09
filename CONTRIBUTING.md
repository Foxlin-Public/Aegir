# Contributing

This repository is Beta-1 scoped.

Contributions should:

- stay inside the existing Beta-1 public SDK surface
- avoid adding Beta-2 features or new trust/KYC models
- keep cross-language behavior aligned with the existing Beta-1 contract
- keep the local MCP wrapper limited to Beta-1 tools
- keep hosted deployment, production runtime, and infrastructure automation out of this repository

Before opening a pull request:

1. validate the package or local MCP wrapper you changed
2. update the relevant integration or local MCP docs
3. keep version references pinned to `0.1.1-beta.1` unless a coordinated release change is being made
