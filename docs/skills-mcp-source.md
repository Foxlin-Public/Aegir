# Foxlin Industries — Skills HTTP MCP and installation source contracts

Unreleased source only. SDK version `0.1.2-beta.1` is unchanged; no package publication or deployment is implied. Runtime qualification is recorded by exact source-bound packet receipts; deployment remains unaccepted.

`skill_metadata_execute_v1` is an additive tool in the Aegir custom stateless HTTP JSON-RPC profile, with output schema `aegir.skill.execution/v1`. The runtime registry contains fourteen tools before caller filtering. The separate SDK stdio registry remains twelve; it has no Skill runner. This is not a claim of Streamable HTTP certification.

The .NET integration source provides `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`. Construct it with an HTTPS origin, the current calling Agent's key and that Agent's own freshly consented `ags1_` Skill reference. Capture once-issued credentials securely; never print them. There is no Human, developer, cookie, proxy or broader-grant fallback. Original `agd3_` and `agd4_` references cannot execute Skills; the original delegated metadata client remains unchanged.

JavaScript/TypeScript, Python, Java and Go have the raw HTTP contract below, with no typed C1 Skill method or claimed C1 runtime acceptance. Their existing non-Skill interfaces remain available.

Send a JSON-RPC `tools/call` to `/mcp` with a separate RPC id and arguments containing exactly:

| Field | Meaning |
|---|---|
| `action` | `execute` or nonsecret `status` |
| `operationId` | Durable 32-character GUID; persist before invoking |
| `skillKey` | Exact approved scoped version key, 64 lowercase hex characters |
| `skillVersion` | Exact reviewed version identifier, at most 64 characters |
| `manifestDigest` | Exact manifest digest, 64 lowercase hex characters |
| `adapterDigest` | Exact accepted actual artifact digest, 64 lowercase hex characters |
| `resourcePolicy` | `self.account.metadata.read` or `group.administration.metadata.read` |
| `resourceAlias` | That grant's own bounded opaque resource alias |
| `scope` | Exactly `security:read` |

Headers are the explicit Agent key and delegation reference. No ambient authorization, developer/session credential or `Idempotency-Key` is accepted for this tool. Registry discovery, publisher text and a manifest never grant execution. Current exact version, approval, enablement, ancestry, resource authority and finite quotas are checked in the canonical service.

Within this C1/C2 metadata MCP contract only the reviewed built-in `audit-troubleshooting` metadata adapter can execute. C3 adds a separate [API-only authentication inspection contract](authentication-skill-source.md); it does not extend this MCP tool. The remaining five original families are represented with execution unavailable pending their own acceptance. There is no external installer, arbitrary adapter, file/network access, account mutation or financial effect.

An `ExecutedMetadata` response contains only the authorized metadata DTO. Exact duplicate execution returns `AlreadyConsumed` without private metadata. `status` returns `CommittedRead` plus an operation-bound server-keyed commitment for a known committed read, even after retirement or grant closure when the original Agent binding remains current. It does not reauthorize private data. The commitment is not a publicly verifiable signature or signed execution receipt. `delivery` never proves client receipt.

Persist the entire original request and reuse its operation id for reconciliation after connection loss, cancellation, restart, redirect, invalid/oversized response or an uncertain server failure. Do not generate a new id or infer Abort. `Unknown/recovery-required` means missing independently verified terminal truth; remain quarantined or reconcile under explicit recovery policy. The client does not retry automatically. Status cannot recover a once-issued lost secret reference or bypass a rotated/revoked Agent credential.

The .NET source disables redirects, cookies and proxies, bounds replies, validates response identity/schema and exposes uncertainty through `DelegatedMcpException`. An explicit certificate SHA256 pin is available only for an owned synthetic loopback host. A pre-execution authorization read is not a strict cross-database commit fence; C1 performs only its bounded canonical metadata read and durable quota/receipt transaction.

## C2 scoped installation and installed grants

C2 adds `POST /v1/skills/v2/installations`, `POST /v1/delegations/v4/root-t1` and `POST /v1/delegations/v4/child`. Exact schemas and request fields are in [OpenAPI](contracts/e2-c2/openapi.json) and the [installation source contract](contracts/e2-c2/skills-installation-source-contract.json). These are restricted source contracts. Foundational Human consent and policy workflows are exercised through genuine canonical reference Probe contracts; the complete public Human issuance journey remains unaccepted.

Installation management authenticates a current Human self-owner or a current administrator of the exact organizational group. Mutations additionally require fresh purpose-bound TOTP. Developer and Agent credentials grant no installation administration. Publisher registration, source review, version approval, organization/Human enablement, installation and execution consent are separate approvals. A reviewed manifest alone cannot execute.

Persist the management `operationId` and exact intent before invoking. `install` generates an immutable Skill installation GUID; callers cannot choose it. Creation binds the exact reviewed Skill/adapter, current application/organization/group/resource, sorted explicit current Agent targets and finite expiry. `enable` is a separate management operation. Read-only `inspect` uses the installation GUID; `status` uses the original mutation's operationId and current original actor/scope. Exact retries return the original immutable outcome together with current state. `Unknown/recovery-required` never proves Abort.

The existing intent's `installationId` still identifies the backend installation. New installed Skill consent uses a separate `skillInstallationId`, purpose `delegation.installed-skill-consent/v1`, policy `c2.skill-intent.v1` and its own canonical digest domain. The v4 root definition pins both the Skill installation GUID and its exact enabling operation as `installation`/`installationApproval`. Fresh current Human consent and administrative approval issue an Agent-bound `ags2_` reference once. Child quotas remain exclusive reservations with no automatic refund.

Use `AegirSkillMcpClient.ForInstalledSkill(httpsOrigin, currentAgentKey, ownInstalledReference, optionalOwnedLoopbackCertificatePin)` in unreleased .NET integration source. Its `ExecuteAsync` and `ReconcileAsync` use the same bounded MCP tool, response schema, deadline and no-ambient-fallback transport. The ordinary constructor accepts only independent C1 `ags1_` authority; the explicit factory accepts only C2 `ags2_` authority. No reference or key belongs in source, logs or documentation. The other four ecosystems have raw contracts only. There is no typed installation-management SDK or stdio Skills executor. HTTP/stdio registry counts remain14/12 before caller filtering.

`uninstall` invalidates that instance and its installed-grant descendants permanently, retaining operation identities and prior nonsecret committed truth. Current authorized cleanup remains available after executable authority is lost. Uninstall removes a scoped relationship; it does not claim physical file deletion. Independently approved C1 grants retain their own authority. Reinstall and upgrade generate new installation identities; earlier references never adopt them. Execution requires fresh exact installed consent and current original authority. A version upgrade requires a strictly greater current approved version; retained overlapping histories prevent rollback. C2 uses a bounded unambiguous SemVer profile. Current artifact changes require genuine review against the current Auth assembly digest.

Installation history retains all terminal records and fails closed at configured capacity: maximum32 permanent instances and4..32 operations per instance, with two operations/events reserved for terminal cleanup and64 events per instance. There is no deletion, speculative pruning or automatic quota refund. Independent witness mismatch, missing/corrupt trust or older restored SQL stays quarantined.

Only the existing reviewed audit-troubleshooting metadata adapter executes. The other six original families, external executable packaging/removal, SDK publication and operational disaster recovery retain their original incomplete scope.

Human Eyes and external deployment: **Deferred — Not Accepted**. Production release is unauthorized.
