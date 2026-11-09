# Aegir protocol-v1 integration (unreleased source)

Copyright Foxlin Industries.

This additive SDK surface uses the current Aegir Web password/MFA exchange and
application-bound authorization API. Existing SDK APIs, package versions and
cryptographic code are preserved. Nothing here publishes a package or changes the
capabilities of an already installed public package.

## Quick start

Build from this directory with the installed/cached toolchain:

```powershell
npm.cmd run build
node examples/integration-scenario.mjs <absolute-private-configuration-path>
```

The JSON-lines example accepts configuration keys `apiBaseUrl`, `webBaseUrl`,
`organizationId`, `applicationId`, `applicationCredential`, `journalPath`,
`username`, `password`, optional `timeoutMs`, and optional
`certificateSha256`. Configuration must be outside source control with
owner-only permissions. Inject actual secrets using the host's secret manager;
never place the configuration contents or raw tickets in logs. The example reads
secrets only from the private file and returns no ticket or credential.

Use an HTTPS API base including its deployment prefix and trailing slash
(for example `https://localhost:57443/apis/`) and the separate Web base
(`https://localhost:57444/`). Normal HTTPS uses the operating system's existing
certificate verification. An explicit SHA256 certificate pin is supported only
for exact localhost/numeric loopback development origins. It is checked before
the HTTP layer obtains the TLS socket; it changes no global certificate trust.
There is no HTTP downgrade, automatic redirect, cookie jar or environment proxy.

Public usage, with confidential values obtained by the host:

```typescript
import { AegirIntegrationClient, FileAuthorizationJournal, AegirMfaRequired }
  from "@foxlin_industries/aegir-security";

const journal = new FileAuthorizationJournal(privateJournalPath, stableStreamBinding);
const client = new AegirIntegrationClient({
  apiBaseUrl, webBaseUrl, organizationId, applicationId, applicationCredential, journal
});
try {
  // Catch AegirMfaRequired, obtain a current user-entered TOTP, and repeat the
  // password exchange with its challengeId and TOTP. A JWT refresh is not proof.
  const session = await client.authenticate(username, password, challengeId, totpCode);
  await client.reconnect();
  const decision = await client.execute(session.accessToken, "write",
    async () => { await applicationTransaction.commitPreparedRecord(); },
    async () => { await applicationTransaction.prepareRecord(); });
  if (!decision.isAuthorized) displayAccessChanged(decision.reason);
} finally { client.close(); journal.close(); }
```

The named host variables and database callbacks are application responsibilities,
not services supplied by this SDK. A host must protect every read/write/save/API
endpoint centrally and roll back its prepared transaction on denial or exception.
Keeping a page or draft open never preserves authorization.

## API and lifecycle

- `authenticate(username,password,challengeId?,totpCode?,signal?)` exchanges fresh
  password/MFA proof at Web `account/organization-access`. It returns a scoped,
  short-lived access session. MFA-required is the typed `AegirMfaRequired`.
- `reconnect(signal?)` disables operations, replays pending batches, snapshots and
  acknowledges current state, then drains to an empty stream before connecting.
- `poll(signal?,acknowledge=true)` polls a healthy connection without resetting it.
  A gap, unknown event, network failure or invalid reply fails closed. Setting
  acknowledge false demonstrates lost-ack recovery and disables access until
  reconnect; it is not a way to permit unacknowledged protected operations.
- `authorize(ticket,"read"|"write",signal?)` always contacts current canonical
  authority. Permit requires HTTP 200, reason `authorized`, a subject alias,
  effective groups and the requested approved permission. Denial/status conflicts,
  duplicate JSON keys and malformed bodies are never permits.
- `execute(ticket,operation,commit,prepare?,signal?)` checks once, optionally
  prepares host work, checks again and invokes commit only on the second permit.
- `disconnect()` disables operations. `close()` aborts owned transport/backoff,
  prevents subsequent callbacks and leaves the caller-owned journal to its host.

Each request has an absolute deadline (default 15 seconds, maximum 120).
AbortSignal cancellation throws a safe machine-readable integration error.
Other unavailable-authority checks return structured denial; the host cannot
override it using event state or an old JWT.

## Journal, ordering and restart

The seven event fields are protocolVersion, transactionId, eventId, groupId,
userId, eventType and groupVersion. User/group IDs are application-scoped aliases;
extra identity fields are rejected. Supported version is 1. Unknown type
reconciles; unsupported version is rejected. All 11 current vocabulary entries
are accepted as invalidations, never grants.

The local single-writer adapter commits event receipt, group version and
invalidation effect together using a flushed temporary file and atomic rename.
Distinct event IDs in the same transaction/version remain distinct effects.
A replayed event ID has no repeated effect; conflicting reuse is rejected. Late
older events get a receipt but cannot replace newer state. Version gaps roll
back the entire batch and demand a fresh snapshot. Snapshot version rollback is
rejected. Snapshot acknowledgment is separate from the application's business
transaction; arbitrary external side effects are not exactly once.

Provide one stable server/organization/application stream binding and private
journal path. A binding mismatch/corrupt journal fails closed. File capacity is
32 MiB /100,000 receipts; exceeding it fails closed. The adapter is for bounded
local reference use, not a multiwriter database. A host-supplied
`AuthorizationJournal` must atomically implement the same receipt/version/effect
boundary and provide its own retention/backup/concurrency policy. Credentials,
passwords and tickets never belong in journals.

A process crash leaves a `.lock` file. The operator must verify no owner process
is alive, preserve the existing journal, remove only that stale lock and
reconnect. Never delete journal history to bypass a mismatch or rollback.
Startup always disconnects even if a prior process persisted connected=true.
Windows process-crash behavior is tested; storage/power-loss qualification and
multi-host locking are host obligations. Restore/reissue backend credentials
using the server's reviewed recovery procedure; source preservation restores no
operational secrets.

## Security and compatibility responsibilities

The application owns endpoint coverage, user-to-record isolation, its database,
secret storage, journal backup, cancellation propagation and error UI. The SDK
owns safe transport, response validation, durable supported journal effects and
fresh checks. Aegir owns canonical current authority, license/device/credential
checks and stream scope.

Authorization linearizes at Aegir's serialized server decision. The later
independent application commit is a separate transaction. The second check
narrows the race but cannot make two databases atomic. Strict commit-time
revocation requires the separately reviewed coordinated fence/mediated-operation
design; this SDK does not claim that guarantee.

Only one active organization per application and `read`/`write` are currently
operational. Multi-organization SaaS, custom permission catalogs, claim/merge,
customer entitlements and transfers are not advertised. Protocol additions or a
new major version require explicit compatibility acceptance. Existing clients
remain source-compatible; callers adopt this additive API deliberately. Java
and Go publication status remains separate from source availability.

