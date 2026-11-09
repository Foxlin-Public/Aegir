# Beta-1 Scope

> **RC1 source update — AEG-RC1-R004:** portable `sign*Payload` compatibility stubs now
> throw (Go panics); `verify*Payload` always rejects. Local envelopes validate integrity only,
> report `isAuthenticated=false`, and reject every non-null signature envelope. Standard SHA-256
> is exposed as `computePayloadDigest` (`compute_payload_digest`, `ComputePayloadDigest`).
> See [the cryptographic compatibility contract](cryptographic-contracts-rc1.md).
> This is unreleased source behavior, not a registry publication.


This repository contains only the Beta-1 public SDK scope.

## Included

- hosted API clients for `.NET`, `Node`, and `Python` â€” the three SDKs released in Beta-1
- `Java` and `Go` client source, **source-only and not released**: present so it can be read and
  built locally, but not published to any registry and not to be depended on. See
  [sdk-manifest.json](../sdk-manifest.json) for the authoritative list.
- public Beta-1 operations:
  - `scanIdentity`
  - `getIdentityGraph`
  - `getIdentityGraphJson`
  - `getExposureSummary`
  - `performAction`
  - `reverseAction`
  - `getActionHistory`
- safe-envelope helpers
- diagnostics hooks
- canonical error semantics
- deprecated fail-closed trust-core compatibility stubs
- budget envelope helpers
- minimal in-memory agent-to-agent protocol
- local Beta-1 MCP stdio wrapper over the public SDK surface

## Excluded

- Beta-2 browser-extension work
- Beta-2 provider expansion
- Beta-2 KYC redesign work
- product-admin/runtime internals that are not part of the public SDK contract
- hosted MCP deployment, production runtime deployment, or infrastructure automation
