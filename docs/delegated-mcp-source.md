# Delegated HTTP MCP source integration

Foxlin Industries. Unreleased source extension; package versions and publication remain unchanged.

The runtime HTTP registry has13 tools; SDK stdio retains its separate12-tool registry. The source-only `delegated_metadata_read_v1` tool calls the canonical B3/B4 T1 metadata admission service. Discovery is descriptive and does not confer authority. Delegated stdio is unavailable and refused; narrowed mode never falls back to an ambient Developer key.

Send the calling Agent key in `X-Aegir-Agent-Key` and its exact root/child opaque reference in `X-Aegir-Delegation`. Do not submit an original Human bearer or put references into tool arguments/discovery. `operationId` is an explicit durable32-hex GUID; JSON-RPC id is correlation only. Inputs are exact `resourcePolicy`, `resourceAlias`, `scope` (`security:read`), and `operationId`. Policies are `self.account.metadata.read` and `group.administration.metadata.read`.

The .NET integration project implements `Foxlin.Aegir.Auth.Delegation.AegirDelegatedMcpClient(Uri, agentKey, delegationReference, optionalLoopbackPin)` and `ReadMetadataAsync(DelegatedMetadataRequest, CancellationToken)`. It owns an immutable HTTPS transport with redirects, cookies and proxies disabled. Explicit pins are local-development loopback only. Never expose credential-bearing settings through diagnostics.

JavaScript/TypeScript, Python, Java and Go have the common raw HTTP contract; no typed delegation convenience method is advertised. The .NET actual backend root/child/three-edge execution is covered by source tests; exact source-bound B5 acceptance receipts govern qualification.

Only `AuthorizedMetadata` contains metadata. Closed/exhausted results can be HTTP200 and must still be denied by Outcome. Exact replay is `AlreadyConsumed` with no metadata. No cached private result may be returned. SDK `DelegatedMcpException.RequiresReconciliation` means preserve the same operation identity; cancellation/timeout/lost response never proves Abort. Current original Human, resource, Agent generation, full lineage, tenant/application/environment, policy, expiry, quota and independent trust are checked per admission. Child quotas are permanently reserved without automatic refunds.

The custom authenticated HTTP compatibility profile is not Streamable HTTP certification. This extension grants no Skill, financial, modification or platform authority. Human Eyes/external deployment remain Deferred — Not Accepted; production release is unauthorized.

HTTP 408, 499, redirects and server/transport failures require reconciliation of the same operation ID. A current refusal or closed grant does not prove that an earlier attempt never committed; retain its journal identity and reconcile authoritative history. The client never automatically retries or substitutes a new operation ID.
