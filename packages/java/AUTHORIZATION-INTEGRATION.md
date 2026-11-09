# Local RC1 authorization integration

Foxlin Industries. Unreleased, source-only Java integration. It is not available
from Maven Central. Existing Beta-1 APIs, version and crypto implementations remain
unchanged. No new dependencies, package publication or machine trust changes.

The installed JDK 11 or newer can compile the library and runnable example:

```powershell
./scripts/test-authorization.ps1
./mvnw.cmd package
java -cp target/classes cloud.foxlin.aegir.security.IntegrationScenario C:/private/integration.json
```

The test script compiles with `--release 11`, executes the retained suite plus the
new native integration tests, and generates then removes a short-lived synthetic
loopback TLS keystore using the installed `keytool`. It downloads nothing. Local
sandbox rules may require authorized loopback execution outside the sandbox.

`AuthorizationIntegration` owns its `HttpClient` and bounded executor. Production
construction uses normal TLS. Redirects, cookies and proxies are disabled. Clean
HTTPS base URLs end in `/` and include the API deployment prefix (usually `/apis/`).
`pinnedLoopbackDevelopment` accepts only HTTPS loopback and an exact certificate
SHA256 pin. It never changes the JVM or operating-system trust store. Request and
body limits are enforced; a strict JSON parser rejects duplicate keys, malformed
types and trailing content without evaluating JavaScript.

Authenticate using `authenticateFresh(username, password, challengeId, totpCode)`.
This calls Web `/account/organization-access`. When `mfaRequired` is true, complete
the genuine password/MFA exchange with the issued challenge and current code.
`FreshAuthentication.accessToken()` is confidential host session material; it is
not a general JWT replacement or an event credential. Never log passwords, access
tickets or backend credentials. The backend key must never enter browser code.

```java
// Read all values from private host configuration, never source literals.
try (FileAuthorizationJournal journal = new FileAuthorizationJournal(privatePath);
     AuthorizationIntegration consumer = new AuthorizationIntegration(
         apiBase, webBase, backendCredential, organizationId, applicationId, journal)) {
    consumer.reconnect();
    AuthorizationIntegration.Decision d = consumer.authorize(scopedTicket, "read", null);
    if (!d.isAuthorized) throw new SecurityException(d.reason);
    // Execute this one read; every subsequent operation needs a new check.
}
```

Use `executeProtected` for a callback gated by a fresh current server decision.
Within an application-owned transaction, call `beforeCommit` immediately before
the actual commit and roll back on denial/error. This narrows ordinary exposure;
it does **not** create an atomic fence between two independent databases. Aegir
linearizes authority in its check transaction. A later revocation may precede the
application commit. Strict commit-time enforcement needs a reviewed coordinated
protocol and is outside this client. Event acknowledgment does not attest that an
arbitrary business side effect completed exactly once.

Startup and disconnect are fail-closed. Explicit `reconnect` drains and acknowledges
durable replay, takes/acknowledges a current authorized snapshot, then drains any
concurrent publications. A normal healthy `poll` does not unnecessarily drop the
connected flag. Every operation still makes a current authoritative check; events,
snapshots and cached claims never authorize a protected operation. Unknown types,
unknown protocol versions, gaps and malformed batches reconcile or fail closed.
An older event never restores a grant. Deduplication uses event ID, not transaction
ID: multiple independent events from one mutation remain distinct effects.

`Journal` is the host storage abstraction. The tested `FileAuthorizationJournal`
commits event receipt hashes, group versions and invalidation counts together. It
stores no credentials or access grants. Its durable binding covers API URL,
organization and application, while allowing backend credential rotation. Snapshots
cannot reduce a known group version. Receipt capacity is 100,000; group-version
capacity is 10,000. Exhaustion fails closed and requires migration to an appropriate
host durable adapter rather than silent deduplication eviction.

Use a private local directory on storage with atomic same-directory replacement.
The file adapter uses forced writes, checksum validation and an OS-backed exclusive
lifetime lock; a second process is rejected, and a process crash releases the lock.
Startup discards the persisted connected flag and reconciles. Checksums detect
corruption, not a malicious host rewriting its own journal. Filesystem power-loss
guarantees and network-share behavior are not certified by local process tests.

Network requests are bounded (15 seconds by default, maximum 30 for pinned local
development); replay is limited to 20 attempts with bounded interruptible backoff.
The host can interrupt a worker to cancel a synchronous operation and schedule its
own aggregate deadline. `close()` cancels in-flight requests, disables operations,
closes the journal and joins its owned transport executor. There is no polling
thread: the host explicitly schedules `poll` and signals known disconnects.

The runnable example reads a private JSON configuration with `apiBaseUrl`,
`webBaseUrl`, `organizationId`, `applicationId`, `applicationCredential`,
`journalPath`, `username`, `password`; optional `certificateSha256`/`timeoutMs`
configure pinned loopback development. Keep this file out of source control.
It accepts one JSON stdin command per line: `requestId` and `op` (`authenticate`,
`reconnect`, `poll`, `check`, `execute`, `disconnect`, `state`, `close`). Protected
commands require `operation: "read"` or `"write"`. Authentication accepts
`challengeId`/`totpCode`; `poll` with `acknowledge: false` persists without ACK and
disables operations until replay reconciliation. Command `timeoutMs` can interrupt
long work. Output never contains the access ticket or backend credential.

Native fixture tests demonstrate transport/parser/journal correctness. They are
separate from the shared actual Aegir service matrix and do not certify parity by
themselves. The example callback counter illustrates enforcement; actual business
record persistence and transaction rollback belong to the integrating application.

The Java file journal retains its OS-lock guard after shutdown. If that existing
guard is present but the state file is missing, reopening fails closed; it does
not initialize empty receipts or group versions. Only the process that atomically
creates a genuinely new guard may initialize missing state. A crash after guard
creation but before the initial durable state is contained as unproven
initialization and requires verified recovery. Never delete the guard to force
access or run an older client against missing established state.
