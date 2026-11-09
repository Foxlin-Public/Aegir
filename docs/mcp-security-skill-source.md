# MCP Security inspection Skill — Foxlin Industries

This unreleased source contract uses the .NET integration consumer
`AegirMcpSecuritySkillApiClient`. It inspects one exact tool in the compiled
Aegir-managed custom HTTP JSON-RPC contract. The operation is
`application.mcp.security.inspect`, at `/v1/skills/v2/mcp-security-inspection`.
It requires a current Agent credential, exact installed Skill delegation,
reviewed Auth artifact, fresh MCP-specific Human consent and current independent
application/group inspection authority. The grant binds the exact tool,
application/environment, managed host, transport and reviewed contract version.

`InspectAsync` uses the caller's explicit operation identity. `ReconcileAsync`
uses that same request and returns nonsecret committed status. There is no
implicit retry or private-result replay. Preserve an uncertain operation and
reconcile it before deciding any next action.

Results include actual required scope/caller class, schema digest and required
input names, source-backed size/deadline bounds and explicit unsupported or
indeterminate controls. A declared schema is not proof of full validation.
Target-dependent and nested authorization remain unevaluated. Hidden/unknown
tools use the same unavailable result without disclosing identity or policy.
Descriptions are inert and never select adapters or scopes.

Inspection never grants tool execution authority. It does not run an inspected
tool, access an arbitrary filesystem, load a plugin or probe a remote host.
`remoteHostAttested` is false: the source authority is the executing Auth assembly.
The custom HTTP profile is distinct from the stdio wrapper; no parity or standard
Streamable HTTP compliance is claimed. Delegated stdio is unsupported. Other
language consumers and the original broader MCP Skill integration obligations
retain their separately recorded status. Package versions and publication status
are unchanged. Runtime acceptance belongs to the E2-C5 evidence, not this guide.

The additive source [OpenAPI contract](contracts/e2-c5/openapi.json) and [route inventory](contracts/e2-c5/api-inventory.json) retain the original versioned contracts. The endpoint accepts 14 exact request fields and at most 4096 request bytes. Inspected MCP dispatcher bounds in metadata describe that separate tool contract; they are not inspection endpoint limits.
