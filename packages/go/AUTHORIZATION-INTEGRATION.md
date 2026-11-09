# Local RC1 authorization integration

Foxlin Industries. Unreleased source integration; no package publication or `go get`
availability is implied. Existing Beta-1 APIs and cryptographic helpers are unchanged.

Build with the installed Go toolchain (module minimum Go 1.22):

```powershell
go test -count=1 ./...
go build -o bin/integration-scenario.exe ./cmd/integration-scenario
```

`NewAuthorizationIntegration(IntegrationConfig, AuthorizationJournal)` owns a TLS
client with redirects, cookies and proxies disabled. Production uses normal TLS
certificate verification. Base URLs must use HTTPS, end in `/`, and include any
deployment prefix (for example the API's `/apis/`). `DevelopmentCertificateSHA256`
is optional and accepts only an exact certificate SHA256 with literal loopback or
localhost HTTPS endpoints. It changes no global trust configuration. Never use a
backend credential in a browser. Configuration, access tickets and passwords are
confidential and must not be logged or serialized.

Call `AuthenticateFresh(ctx, username, password, challengeID, totpCode)` against the
actual Web `/account/organization-access` contract. When `MFARequired` is true,
perform the supported fresh password/MFA exchange again with `ChallengeID` and the
current code. The returned opaque `AccessToken` belongs in private process/session
storage. No old JWT, event, snapshot or cached group claim creates a new ticket.

```go
// Obtain cfg and credentials from host-owned private configuration.
journal, err := aegirsecurity.NewFileAuthorizationJournal(privateJournalPath)
if err != nil { return err }
consumer, err := aegirsecurity.NewAuthorizationIntegration(cfg, journal)
if err != nil { journal.Close(); return err }
defer consumer.Close()
if err := consumer.Reconnect(ctx); err != nil { return err }
decision := consumer.Authorize(ctx, scopedHumanTicket, "read", "")
if !decision.IsAuthorized { return errors.New(decision.Reason) }
// Perform this one protected read. A different operation needs another check.
```

`ExecuteProtected` invokes a callback only after a fresh current server permit.
Inside an application-owned database transaction, prepare changes, call
`BeforeCommit` immediately before committing, and roll back if it denies or errors.
The server check linearizes in Aegir's authorization transaction. A revocation may
still commit between that completed check and an independent application's commit.
This helper **does not provide strict cross-database atomic revocation**. The host
must assess that remaining race; a coordinated fence is a separate server design.

The consumer starts disconnected. Explicit `Reconnect` first drains durable
unacknowledged replay, then takes and acknowledges a current authorized snapshot,
then drains any concurrent publications. `Poll` preserves healthy connected state
while polling normally. Network errors, invalid responses, event gaps or stale
server state disable operations until reconciliation. Every protected operation
still calls the server. Empty healthy polling cannot confer authority by itself.
There is no automatic background goroutine: the host schedules bounded polling
and must call `Disconnect` when it knows connectivity is lost.

The journal interface commits receipt identity, monotonic group version and the
demonstrated invalidation counter atomically. Distinct events sharing a transaction
are distinct effects. Duplicate event IDs do not repeat effects. An older event
gets a receipt without an effect; it cannot restore access. Unknown protocol/type
or a version gap requires a current snapshot. Unknown personal data fields are
rejected on the seven-field event wire contract. Snapshots never grant operations.

The local file adapter stores opaque receipt hashes/versions, never credentials or
permissions, with a SHA256 corruption check and same-directory forced replacement.
It binds the journal to API URL, organization and application; credential rotation
does not change that stream binding. Use a private local directory, one journal per
stream, and normal shutdown. At most 100,000 event receipts and 10,000 group versions
are retained; capacity exhaustion fails closed instead of deleting receipts. Hosts
may implement the interface in an application database for a longer-running service.

The Go adapter now takes an OS-held lock on a stable `.owner` sidecar. The OS
releases ownership after process death. A complete persistent `.lock` v2 guard
prevents an older O_EXCL SDK from bypassing that lock. Both files intentionally
remain after clean shutdown. Never delete or replace either while any owner may
be alive; timestamps and PIDs are not ownership proof. Two new SDK processes
competing after a crash still admit only one owner.

A valid established journal reopens disconnected and retains receipt IDs, version
high watermarks and invalidation counts. Missing, truncated, corrupt, oversized or
capacity-exhausted state fails closed and remains available for investigation.
The checksummed file is bounded before allocation. Reconnect must still drain /
acknowledge replay, reconcile a fresh snapshot and make current server checks.
A lost ACK does not repeat an effect; an older grant after revocation cannot
restore access. The counter is a journal effect, not an arbitrary business commit.

Windows support is restricted to fixed local NTFS storage, using `LockFileEx`.
Linux uses `flock` on qualified local ext-family, tmpfs or overlay filesystems.
Other platforms/filesystems fail closed. UNC paths are rejected before filesystem
mutation. Network shares, malicious same-account filesystem manipulation, hardware
failure and power-loss durability are not qualified by process-crash tests.
The private parent directory is a host prerequisite; Go file mode is not a Windows
ACL configuration service.

For a D1 crash lock with no v2 marker, stop and independently verify every legacy
owner is gone, preserve and validate a copy of the checksummed journal, then have
an authorized operator remove only that old unmarked lock. No automatic age/PID
cleanup is provided. The next new SDK takes OS ownership and installs a complete
v2 guard without replacing a racing legacy lock. A D1 clean shutdown with no lock
can be upgraded directly. Never downgrade to D1 against a v2-guarded journal or
remove its guard to force access. Recover missing/corrupt data from a verified
backup into a separately controlled path and reconcile before protected work.

`context.Context` bounds requests/replay and propagates cancellation. Each request
has an additional timeout (15 seconds by default; maximum 30 seconds). Replay has
20 attempts and bounded backoff. `Close` cancels active work, closes owned idle
connections and the journal, and waits for serialized consumer operations to stop.

The runnable line-JSON example accepts **one private configuration path**:

```powershell
./bin/integration-scenario.exe C:/private/integration.json
```

Required private keys are `apiBaseUrl`, `webBaseUrl`, `organizationId`,
`applicationId`, `applicationCredential`, `journalPath`, `username`, `password`;
optional `certificateSha256` and `timeoutMs` configure pinned local development.
Do not commit that file. Feed one JSON command per stdin line, using `requestId`
and `op`: `authenticate`, `reconnect`, `poll`, `check`, `execute`, `disconnect`,
`state`, `close`. Checks/execution also require `operation: "read"` or `"write"`.
MFA accepts `challengeId`/`totpCode`; `poll` with `acknowledge: false` demonstrates
an applied batch whose acknowledgment is lost. The ticket is kept only in memory.
Output contains safe result/reason and journal counts, never tokens or credentials.
`execute` demonstrates a fresh check and before-commit revalidation with a local
callback counter; genuine persistent application transactions are the host's duty.

Native synthetic TLS tests are transport/adapter tests. Shared real Aegir service
tests provide separate integration evidence; one kind does not replace the other.
