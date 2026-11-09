# Aegir Python protocol-v1 integration (unreleased source)

Copyright Foxlin Industries.

This additive SDK surface uses the current Aegir Web password/MFA exchange and
application-bound authorization API. Existing SDK APIs, package versions and
cryptographic code are preserved. Nothing here publishes a package or changes the
capabilities of an already installed public package.

## Quick start

Build from this directory with the installed/cached toolchain:

```powershell
python -m unittest discover -s tests -v
python examples/integration_scenario.py <absolute-private-configuration-path>
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

```python
from foxlin_aegir_security import (
    AegirIntegrationClient, AegirMfaRequired, SqliteAuthorizationJournal)

journal = SqliteAuthorizationJournal(private_journal_path, stable_stream_binding)
try:
    with AegirIntegrationClient(
        api_base_url=api_base_url, web_base_url=web_base_url,
        organization_id=organization_id, application_id=application_id,
        application_credential=application_credential, journal=journal) as client:
        # Catch AegirMfaRequired; repeat fresh password exchange with its
        # challenge_id and a current user-entered TOTP.
        session = client.authenticate(username, password,
            challenge_id=challenge_id, totp_code=totp_code)
        client.reconnect()
        decision = client.execute(session["accessToken"], "write",
            application_transaction.commit_prepared_record,
            prepare=application_transaction.prepare_record)
        if not decision["isAuthorized"]:
            display_access_changed(decision["reason"])
finally:
    journal.close()
```

The named host variables and database callbacks are application responsibilities,
not services supplied by this SDK. A host must protect every read/write/save/API
endpoint centrally and roll back its prepared transaction on denial or exception.
Keeping a page or draft open never preserves authorization.

## API and lifecycle

- `authenticate(username,password,challenge_id=...,totp_code=...,cancel=...)` exchanges fresh
  password/MFA proof at Web `account/organization-access`. It returns a scoped,
  short-lived access session. MFA-required is the typed `AegirMfaRequired`.
- `reconnect(cancel=...)` disables operations, replays pending batches, snapshots and
  acknowledges current state, then drains to an empty stream before connecting.
- `poll(cancel=...,acknowledge=True)` polls a healthy connection without resetting it.
  A gap, unknown event, network failure or invalid reply fails closed. Setting
  acknowledge false demonstrates lost-ack recovery and disables access until
  reconnect; it is not a way to permit unacknowledged protected operations.
- `authorize(ticket,"read"|"write",cancel=...)` always contacts current canonical
  authority. Permit requires HTTP 200, reason `authorized`, a subject alias,
  effective groups and the requested approved permission. Denial/status conflicts,
  duplicate JSON keys and malformed bodies are never permits.
- `execute(ticket,operation,commit,prepare=...,cancel=...)` checks once, optionally
  prepares host work, checks again and invokes commit only on the second permit.
- `disconnect()` disables operations. `close()` aborts owned transport/backoff,
  prevents subsequent callbacks and leaves the caller-owned journal to its host.

Each request has an absolute deadline (default 15 seconds, maximum 120).
A threading.Event cancellation throws a safe machine-readable integration error.
Other unavailable-authority checks return structured denial; the host cannot
override it using event state or an old JWT.

## Journal, ordering and restart

The seven event fields are protocolVersion, transactionId, eventId, groupId,
userId, eventType and groupVersion. User/group IDs are application-scoped aliases;
extra identity fields are rejected. Supported version is 1. Unknown type
reconciles; unsupported version is rejected. All 11 current vocabulary entries
are accepted as invalidations, never grants.

The SQLite adapter commits event receipt, group version and invalidation effect
in one BEGIN IMMEDIATE transaction with WAL and synchronous=FULL, using only the
Python standard library. Concurrent adapter instances serialize database writes.
Distinct event IDs in the same transaction/version remain distinct effects.
A replayed event ID has no repeated effect; conflicting reuse is rejected. Late
older events get a receipt but cannot replace newer state. Version gaps roll
back the entire batch and demand a fresh snapshot. Snapshot version rollback is
rejected. Snapshot acknowledgment is separate from the application's business
transaction; arbitrary external side effects are not exactly once.

Provide one stable server/organization/application stream binding and private
journal path. A binding mismatch/corrupt journal fails closed. Journal growth and SQLite capacity are host retention/monitoring responsibilities.
The adapter is a local reference database, not a distributed multi-host database. A host-supplied
`AuthorizationJournal` must atomically implement the same receipt/version/effect
boundary and provide its own retention/backup/concurrency policy. Credentials,
passwords and tickets never belong in journals.

SQLite recovers committed journal transactions after a process restart. Startup
always disconnects even if a prior process persisted connected=True. Host backup
must use SQLite's backup API or a quiescent consistent database, including WAL;
copying a live main file alone is unsafe. Restore/reissue backend credentials
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

