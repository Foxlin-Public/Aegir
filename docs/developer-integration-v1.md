# Developer integration v1

Foxlin Industries. Unreleased source integration; no package publication or production release is implied. Existing registry metadata remains in `sdk-manifest.json`. Java and Go remain source distributions. The new integration is additive to existing client and cryptographic APIs.

The server supports one active organization per ApplicationId and the approved `read` and `write` operations. An application backend owns its app-bound subscriber credential, durable journal and authenticated user ticket. A browser must never receive the backend credential. Events carry application-specific aliases and invalidate local state; they never authorize an operation.

The .NET PostgreSQL adapter's [format2 retained-history contract](postgres-consumer-v2.md) requires explicit first-install establishment and open-only restart, bounded row/byte admission, exact duplicate/conflict checking and retained group/subject high-watermarks. Controlled restoration requires a minimum checkpoint retained independently by the host before acknowledgment; the event client does not automatically provide that custody. Other language adapters have their own documented storage boundaries. Source/contract parity does not certify the entire historical SDK surface or publish a package.

| Ecosystem | Source entry | Persistent adapter | Language guide |
|---|---|---|---|
| .NET 10 | `packages/dotnet/integration/Foxlin.Aegir.Integration.csproj` | File journal or PostgreSQL | [Guide](../packages/dotnet/integration/README.md) |
| TypeScript / JavaScript, Node 18+ | `packages/npm/src/integration.ts` | File journal | [Guide](../packages/npm/INTEGRATION.md) |
| Python 3.10+ | `packages/python/foxlin_aegir_security/integration.py` | SQLite journal | [Guide](../packages/python/INTEGRATION.md) |
| Java 11+ | `packages/java/src/main/java/cloud/foxlin/aegir/security/AuthorizationIntegration.java` | File journal | [Guide](../packages/java/AUTHORIZATION-INTEGRATION.md) |
| Go | `packages/go` authorization integration | File journal | [Guide](../packages/go/AUTHORIZATION-INTEGRATION.md) |

Use the exact native prerequisites recorded by each guide and the D1 acceptance evidence. Source builds use installed or cached dependencies. None of these instructions activates infrastructure, publishes packages or enables CI.

## Start an application backend

1. Inject clean HTTPS API and Web base URLs, the exact organization/application context and a bounded app credential from your backend secret store. Production transport uses normal certificate validation. Only explicit local-development clients can use an exact certificate SHA256 pin, and only on HTTPS loopback. Redirects, cookies and implicit proxies cannot forward credentials.
2. Open a journal in a directory or database owned by this application. Bind a file/SQLite journal to the API/organization/application context. The PostgreSQL adapter requires a distinct consumer ID and explicitly selected schema per application. Protect that directory, database account, backups and file permissions; local adapters are not encrypted secret stores and are not designed for hostile shared directories or symlink substitution.
3. Complete genuine Web password authentication and any returned MFA challenge. Keep the resulting scoped ticket server-side. Failed authentication cannot preserve an earlier ticket. The backend credential and the human ticket are different authorities.
4. Explicitly reconnect on startup, drain durable replay, apply a current authorized snapshot and drain subsequent events before admitting protected operations. A persisted connected flag is never trusted after restart.
5. Call a fresh canonical check for every protected read/write. Use the provided callback helper or centralized application middleware. On denial, do not call the business callback. An open page or retained draft does not preserve write permission.
6. For a write, open an application transaction, check authority, prepare changes and revalidate immediately before commit. Roll back/dispose preparation on denial, cancellation or uncertainty. The .NET `ExecuteRevalidatedAsync` helper models both checks; other guides show their language's equivalent.
7. Poll a healthy stream with the ordinary poll method. Explicit reconnect is for startup, disconnection, uncertain state or recovery. Do not repeatedly disconnect a healthy consumer merely to poll.
8. Dispose/close the client and release the journal lease on shutdown. Go's current local adapter fails closed on a stale crash lock; verify there is no live owner before any documented operator lock recovery. Automatic hard-crash lock recovery is not claimed.

## Errors and reauthentication

Treat `event_reconciliation_required` as a need to reconcile, never as permission to use a cached grant. An unavailable server, unknown event version/type, malformed response, contradictory status, invalid operation or canceled request cannot produce a permit. Denials are structured; application UX can display a changed-access notice without closing a page.

After membership or license revocation and regrant, the old scoped ticket remains invalid. Authenticate again through Aegir. Do not fabricate a new ticket from an event, cached JWT group claims, a user ID or a changed journal flag. Rotating/revoking a backend credential requires explicit secure configuration replacement and authorized reconciliation.

## Event protocol and persistence

Protocol 1 has exactly seven fields: `protocolVersion`, `transactionId`, `eventId`, `groupId`, nullable `userId`, `eventType`, `groupVersion`. Deduplicate by event ID. Different events in the same transaction are independently processable. Commit receipt, monotonic version and demonstrated invalidation effect atomically before acknowledgment. A lost acknowledgment permits redelivery, not a second invalidation effect. Older versions never restore authority. Unknown versions/types require reconciliation; snapshots may not roll a retained group high watermark backward.

The supported vocabulary is `granted`, `revoked`, `adminGranted`, `adminRevoked`, `permissionChanged`, `licenseGranted`, `licenseRevoked`, `membershipChanged`, `suspended`, `restored`, `groupPolicyChanged`. A future grant-like string is not a grant. Snapshot subjects describe current state but still do not replace an operation check.

Acknowledgment advances an authenticated event-delivery cursor. It does not attest that an arbitrary external business transaction committed. Applications need their own operation IDs, database constraints, idempotency receipts, rollback and recovery policy. Journal restoration always requires current server reconciliation; a restored snapshot that cannot be trusted must remain denied.

## Responsibility and compatibility

| Boundary | Aegir / SDK responsibility | Application / operator responsibility |
|---|---|---|
| Authority | Current principal, tenant, scope, membership, license, source grant and epoch checks | Protect every relevant endpoint and request the exact operation |
| Transport | HTTPS, strict bounded parsing, no credential redirects, bounded deadlines | Secure endpoint configuration and credential injection; do not log tickets/keys |
| Persistence | Supported journal transaction/deduplication and replay | Protect storage, retain backups and coordinate business-effect idempotency |
| Recovery | Reject retired key fingerprints under a new trusted external generation | Quarantine restored state, rotate outside-DB keys, reconcile approved authority and reissue credentials |
| UI | Structured denial/change notification | Decide whether to preserve drafts or an open page; never bypass denial |

The canonical API is OpenAPI 3.1; the event schema is JSON Schema 2020-12, protocol 1. Required known fields retain their meaning and type. Optional outer-response additions may be ignored after validation. The seven-field event envelope is closed; incompatible changes require a new negotiated protocol. All supported clients reject duplicate JSON keys and malformed permit responses. Limits and status semantics come from the canonical server contract, not an SDK model generator.

The canonical runtime contracts live in `Aegir/Docs/contracts/v1` in the private workspace; this SDK's copied contract directory contains developer-safe specifications only. Administrative operations remain explicitly sensitive and require current administrative authority; a general application subscriber credential does not grant those permissions. The inventory lists incompletely documented routes separately. R012, MCP and Skills are not declared complete by this integration.

## Migration and commit boundary

Existing cryptographic implementations and legacy public SDK examples are preserved. Deprecated keyless trust-core helpers are not authentication or cryptography. This pass does not change the TLS-versus-envelope distinction or publish a new package version.

The server's backend credential fingerprint now uses a purpose-separated HMAC derived from its active signing key. Historical unkeyed fingerprints require canonical review/reissuance, with no compatibility fallback. Coordinate active signing-key rotation across hosts and app credentials. Do not restore retired validation keys into an untrusted recovery generation. Source-only Git preservation does not restore operational secrets.

The final Aegir check linearizes inside the server's authority transaction. The application's later database commit is separate; revalidation narrows but does not remove a concurrent revocation interval. The reviewed coordinated-fence design is **designed, not implemented or accepted**. No SDK claims strict atomic revocation across independent databases or exactly-once arbitrary business effects.

Human Eyes: Deferred — Not Accepted. External deployment: Deferred — Not Accepted.
# Agent message source contract

Foxlin Industries. The existing [agent message HTTP contract](contracts/v1/agent-messages.md) covers `/v1/ai/messages` and `/v1/ai/messages/receive`. Existing Node and Python source clients provide `sendAgentMessage` and `receiveAgentMessage`; their genuine local backend qualification is separate from publication. This does not add convenience methods to the other ecosystems or grant developer credentials Agent authority. Open an Agent-owned transaction first. Preserve the returned envelope for recipient handoff: the direct API has no durable inbox or replayable lost-send response, and one-time local opening does not establish an external business outcome.

# Signed handoff source contracts

The eight existing core handoff operations are documented in
[signed-handoff.md](contracts/v1/signed-handoff.md). Use an authenticated RP backend
relay; keep its credential on the server. A device signs the exact server-returned
canonical bytes after current Human owner approval. Sessions invalidate on API
restart, and a lost bearer result requires a new ceremony. This source contract
qualifies a `trusted_device` application grant only. Package versions are unchanged.

# QR and launch adapter source contracts

The six existing adapters are documented in
[handoff-adapters.md](contracts/v1/handoff-adapters.md). QR lookup requires the
original authenticated RP relay. Locators, launch descriptors and provider choices
are presentation metadata; completion still requires the exact current G1 device
proof. Mobile push selects a path without delivering a notification. Desktop URI
construction does not certify OS activation. Package versions remain unchanged.



## C1 Skills source addendum

See [Skills HTTP MCP source contract](skills-mcp-source.md). The unreleased .NET integration source adds `AegirSkillMcpClient.ExecuteAsync` and `ReconcileAsync`; JavaScript/TypeScript, Python, Java and Go expose this C1 capability only through the raw HTTP contract, without typed C1 methods or claimed C1 native parity. It requires a newly consented `ags1_` reference and current Agent identity. Old no-Skill grants cannot execute Skills. Runtime HTTP registry:14 before filtering; SDK stdio registry:12 with no Skill runner. This source-only addition changes no SDK package version and authorizes no publication or deployment. Runtime qualification is recorded by exact source-bound acceptance receipts; deployment remains unaccepted.


## C2 installed Skills source addendum

The additive [Skills source contract](skills-mcp-source.md#c2-scoped-installation-and-installed-grants) models current Human installation management and separately consented installed grants. The .NET source explicitly selects `AegirSkillMcpClient.ForInstalledSkill` for new `ags2_` references; the default constructor retains C1 `ags1_` mode. All five ecosystems may use the raw installation HTTP contract; no typed management SDK or installed-Skill parity in the other four languages is claimed. Uninstall is terminal for that instance. Explicit reinstall creates a fresh identity and requires fresh execution consent. Package versions and publication status remain unchanged.
