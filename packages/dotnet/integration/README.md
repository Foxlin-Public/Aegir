# .NET developer integration v1

Foxlin Industries. Local unreleased source; not a published NuGet package. Requires .NET 10 and the already installed/cached Npgsql 9.0.3 dependency. The source is an exact copy of the runtime's genuine public consumer, file/PostgreSQL journal and typed integration client. It contains no server engine, administrative store or server migrations.

Build locally from this directory:

```powershell
dotnet build Foxlin.Aegir.Integration.csproj --source C:\Users\YourName\.nuget\packages -p:NuGetAudit=false
```

Reference the project from your backend. Namespace: `Foxlin.Aegir.Auth.AuthorizationEvents`.

```csharp
// Inject these values from backend configuration. Do not embed or log credentials.
using var journal = new FileAuthorizationEventConsumerStore(journalPath,
    apiBaseUrl + "|" + organizationId + "|" + applicationId);
using var aegir = new AegirIntegrationClient(new(
    new Uri(apiBaseUrl), new Uri(webBaseUrl), organizationId, applicationId,
    applicationCredential), journal);
```

Authenticate, reconcile and check each operation:

```csharp
var authentication = await aegir.AuthenticateAsync(username, password, ct: cancellationToken);
if (!authentication.Authenticated) return;
await aegir.Events.ReconnectAsync(cancellationToken);
var read = await aegir.AuthorizeAsync("read", cancellationToken);
if (!read.IsAuthorized) return;
// For a write, own and dispose/roll back the transaction if preparation is denied.
var decision = await aegir.ExecuteRevalidatedAsync("write",
    prepare: ct => PrepareUncommittedChangesAsync(ct),
    commit: ct => CommitPreparedChangesAsync(ct), ct: cancellationToken);
```

Routine healthy polling uses `Events.PollAsync`; reconnect is required after startup/disconnection. The callback is never invoked on denial. Preparation must not commit. Revocation between the final authority decision and an independent business commit remains a documented race. Disposing closes owned transports; the caller owns and disposes the journal.

`PostgresAuthorizationEventConsumerStore` is available when the application already uses PostgreSQL. Explicitly EstablishAsync once in an application-owned existing schema; on restart InitializeAsync opens existing state only. Use an immutable API/organization/application scopeBinding and distinct consumer ID. Retain ReadCheckpointAsync receipts outside the database rollback domain before ACK; pass expectedCheckpoint when restoring. Legacy/partial/missing journals fail closed. Default retained bounds are10,000 rows per history table and16MiB logical bytes; exact duplicates need no growth at capacity. See [format2 retention and recovery](../../../../docs/postgres-consumer-v2.md). Use a separate application database/role in real integrations. File journals need a private host-owned directory, exclusive writer ownership and secured backup/retention procedures. Neither adapter persists authentication tickets or backend credentials.

The full runnable JSON-line example is retained in the private runtime workspace at `Aegir/tools/IntegrationScenario`; its source is also mirrored under this directory's `example`. Pass a private configuration file path, then issue `authenticate`, `reconnect`, `check`, `execute`, `poll`, `disconnect`, `state`, `close` commands. Credentials and the human ticket are never printed. An optional certificate SHA256 pin is strictly for explicit HTTPS loopback development. Production uses normal trust validation.

If referencing the private Auth source assembly that already defines these consumer types, use that assembly's implementation rather than referencing a second copy of the same types. Existing published package compatibility remains separately tested; the new source is not claimed to exist in an earlier NuGet release.

See the [common integration guide](../../../docs/developer-integration-v1.md) for errors, event acknowledgment, storage, reauthentication, supported limits, recovery and security responsibilities.
