// Copyright Foxlin Industries. Local reference integration; no package publication is implied.
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Text.Json;

namespace Foxlin.Aegir.Auth.AuthorizationEvents;

/// <summary>Minimal protocol v1 notification. Its contents are never accepted as an access credential.</summary>
/// <param name="ProtocolVersion">Wire protocol version; version 1 is supported.</param>
/// <param name="TransactionId">Opaque identity of the committed authoritative change.</param>
/// <param name="EventId">Stable publication identity used for deduplication.</param>
/// <param name="GroupId">Application-scoped opaque group alias.</param>
/// <param name="UserId">Application-scoped subject alias, or null for a group policy change.</param>
/// <param name="EventType">Change vocabulary; an unknown type requires reconciliation.</param>
/// <param name="GroupVersion">Monotonic application/group projection version.</param>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record AuthorizationNotification([property: JsonRequired] int ProtocolVersion, [property: JsonRequired] string TransactionId, [property: JsonRequired] string EventId,
    [property: JsonRequired] string GroupId, [property: JsonRequired] string? UserId, [property: JsonRequired] string EventType, [property: JsonRequired] long GroupVersion);
/// <summary>A durable pending delivery or an explicit reconciliation/backoff response.</summary>
/// <param name="DeliveryId">Opaque server-issued acknowledgment identity, absent when no batch was issued.</param>
/// <param name="Events">Minimal notifications in publication order.</param>
/// <param name="RequiresSnapshot">True when replay cannot establish current state.</param>
/// <param name="Reason">Non-sensitive machine-readable reconciliation/backoff reason.</param>
/// <param name="RetryAfterSeconds">Bounded delay before another poll.</param>
public sealed record AuthorizationNotificationBatch([property: JsonRequired] string? DeliveryId, [property: JsonRequired] IReadOnlyList<AuthorizationNotification> Events,
    [property: JsonRequired] bool RequiresSnapshot, [property: JsonRequired] string? Reason, [property: JsonRequired] int RetryAfterSeconds);
/// <summary>One currently effective application subject in an authoritative snapshot.</summary>
/// <param name="UserId">Application-scoped opaque subject alias.</param>
/// <param name="Allowed">Current effective access state; it never replaces a per-operation server check.</param>
/// <param name="AuthorizationEpoch">Current scoped authorization epoch.</param>
public sealed record AuthorizationConsumerSubject([property: JsonRequired] string UserId, [property: JsonRequired] bool Allowed, [property: JsonRequired] long AuthorizationEpoch);
/// <summary>An authorized application/group projection and its current subjects.</summary>
/// <param name="GroupId">Application-scoped opaque group alias.</param>
/// <param name="GroupVersion">Version captured by the authoritative snapshot.</param>
/// <param name="Subjects">Only subjects relevant to this authorized group/application projection.</param>
public sealed record AuthorizationConsumerGroup([property: JsonRequired] string GroupId, [property: JsonRequired] long GroupVersion, [property: JsonRequired] IReadOnlyList<AuthorizationConsumerSubject> Subjects);
/// <summary>An atomic authoritative snapshot with a server-held stream watermark.</summary>
/// <param name="SnapshotId">Opaque reconciliation identity; the client cannot choose its watermark.</param>
/// <param name="Groups">Current authorized application/group projections.</param>
public sealed record AuthorizationConsumerSnapshot([property: JsonRequired] string SnapshotId, [property: JsonRequired] IReadOnlyList<AuthorizationConsumerGroup> Groups);
/// <summary>The current server decision for one protected operation.</summary>
/// <param name="IsAuthorized">Whether this operation is currently permitted.</param>
/// <param name="Reason">Machine-readable current decision reason.</param>
/// <param name="ApplicationSubjectId">Opaque application-specific subject, when disclosable.</param>
/// <param name="AuthorizationEpoch">Current scoped epoch.</param>
/// <param name="EffectiveGroupIds">Application-specific aliases of effective groups.</param>
/// <param name="Permissions">Currently approved application operation names.</param>
public sealed record AuthorizationProtectedDecision([property: JsonRequired] bool IsAuthorized, [property: JsonRequired] string Reason, [property: JsonRequired] string? ApplicationSubjectId,
    [property: JsonRequired] long AuthorizationEpoch, [property: JsonRequired] IReadOnlyList<string> EffectiveGroupIds, [property: JsonRequired] IReadOnlyList<string> Permissions);
/// <summary>A backend-bound current check using a freshly authenticated scoped human ticket.</summary>
/// <param name="AccessToken">Opaque scoped human access ticket; never log this value.</param>
/// <param name="Operation">The exact application permission required for this operation.</param>
public sealed record AuthorizationConsumerCheckRequest(string AccessToken, string Operation);
/// <summary>Acknowledges only a batch actually delivered to this authenticated application.</summary>
/// <param name="DeliveryId">The issued delivery identity.</param>
public sealed record AuthorizationConsumerAcknowledgment(string DeliveryId);
/// <summary>Confirms processing of a server-issued authoritative snapshot.</summary>
/// <param name="SnapshotId">The issued snapshot identity.</param>
public sealed record AuthorizationConsumerSnapshotAcknowledgment(string SnapshotId);

/// <summary>A durable transaction must commit receipt, group version and demonstrated effect together.</summary>
public interface IAuthorizationEventConsumerStore
{
    /// <summary>Atomically commits deduplication receipts, versions and the consumer's demonstrated effects.</summary>
    /// <param name="events">A bounded ordered batch obtained from the authenticated server.</param>
    /// <param name="ct">Cancels the entire consumer transaction.</param>
    ValueTask<AuthorizationConsumerApplyResult> ApplyAsync(IReadOnlyList<AuthorizationNotification> events, CancellationToken ct = default);
    /// <summary>Replaces local projection state from one current server snapshot.</summary>
    /// <param name="snapshot">The authenticated authoritative snapshot.</param>
    /// <param name="ct">Cancels the entire snapshot transaction.</param>
    ValueTask ApplySnapshotAsync(AuthorizationConsumerSnapshot snapshot, CancellationToken ct = default);
    /// <summary>Persists whether this consumer has completed reconnection.</summary>
    /// <param name="connected">False prevents reliance on previously cached state.</param>
    /// <param name="ct">Cancels the persistence operation.</param>
    ValueTask SetConnectedAsync(bool connected, CancellationToken ct = default);
}
/// <summary>Reports committed journal effects or a fail-closed reconciliation requirement.</summary>
/// <param name="NewEffects">Number of newly committed effects, excluding duplicate/stale events.</param>
/// <param name="RequiresSnapshot">True when no batch effects were committed because reconciliation is necessary.</param>
public sealed record AuthorizationConsumerApplyResult(int NewEffects, bool RequiresSnapshot);

/// <summary>
/// Genuine HTTP reference backend. Call ReconnectAsync before protected operations after every startup or disconnect.
/// The public constructor owns an HTTPS-only client with redirects and cookies disabled.
/// </summary>
public sealed class AuthorizationEventReferenceConsumer : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _credential;
    private readonly IAuthorizationEventConsumerStore _store;
    private readonly Func<string, CancellationToken, ValueTask>? _onDenied;
    private volatile bool _connected;
    private int _generation;
    private readonly CancellationTokenSource _lifetime = new();
    /// <summary>True only after this instance completed reconciliation; never a cached access grant.</summary>
    public bool IsConnected => _connected && !_disposed;
    private bool _ownsHttpClient;
    private volatile bool _disposed;
    private readonly SemaphoreSlim _processing = new(1, 1);

    /// <summary>Owns a client that cannot forward the application credential through automatic redirects or cookies.</summary>
    /// <param name="baseAddress">An absolute HTTPS deployment base address ending with a slash, including any path prefix.</param>
    /// <param name="applicationCredential">The once-issued app-bound credential in credentialId:secret form.</param>
    /// <param name="store">Consumer-owned durable transactional journal.</param>
    /// <param name="onDenied">Optional user-experience callback; it cannot override an authorization denial.</param>
    public AuthorizationEventReferenceConsumer(Uri baseAddress, string applicationCredential, IAuthorizationEventConsumerStore store,
        Func<string, CancellationToken, ValueTask>? onDenied = null)
        : this(CreateOwnedClient(baseAddress, allowLoopbackHttpForTests: false, applicationCredential, store), applicationCredential, store, onDenied)
    { _ownsHttpClient = true; }

    // Friend-test injection only. The supplied TestServer handler must not follow redirects;
    // ownership stays with its caller. Public consumers cannot supply an unsafe redirecting client.
    internal AuthorizationEventReferenceConsumer(HttpClient http, string applicationCredential, IAuthorizationEventConsumerStore store,
        Func<string, CancellationToken, ValueTask>? onDenied = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        if (string.IsNullOrWhiteSpace(applicationCredential) || applicationCredential.Length > 512 || applicationCredential.Any(c => c < 33 || c > 126)) throw new ArgumentException("A bounded printable application backend credential is required.");
        _credential = applicationCredential;
        _onDenied = onDenied;
    }

    /// <summary>Replays durable unacknowledged batches; a retention/version gap requires a current authoritative snapshot.</summary>
    /// <param name="ct">Cancels reconnection while leaving protected operations disabled.</param>
    public ValueTask ReconnectAsync(CancellationToken ct = default) => ProcessEventsAsync(true, ct);

    /// <summary>Polls a healthy stream without creating an artificial disconnected interval. Every protected operation still contacts Aegir.</summary>
    public ValueTask PollAsync(CancellationToken ct = default) => ProcessEventsAsync(false, ct);

    /// <summary>Optionally commits the journal without ACK, supporting host-controlled acknowledgment recovery tests.
    /// The stream remains disconnected until a later replay has been durably acknowledged.</summary>
    public ValueTask PollAsync(bool acknowledge, CancellationToken ct = default) => ProcessEventsAsync(false, ct, acknowledge);

    private async ValueTask ProcessEventsAsync(bool reconnect, CancellationToken cancellationToken, bool acknowledge = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        CancellationToken ct = linked.Token;
        int generation = Volatile.Read(ref _generation);
        await _processing.WaitAsync(ct);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!reconnect && !_connected) throw new InvalidOperationException("Reconnect is required.");
            if (reconnect) { _connected = false; await _store.SetConnectedAsync(false, ct); }
            bool reconciled = false;
            for (int attempt = 0; attempt < 20; attempt++)
            {
                AuthorizationNotificationBatch batch = await GetBatchAsync(ct);
                if (batch.Events is null || batch.Events.Count > 100 || batch.RetryAfterSeconds is < 0 or > 30)
                    throw new System.Text.Json.JsonException("Invalid delivery batch.");
                if (batch.RequiresSnapshot)
                {
                    _connected = false;
                    await _store.SetConnectedAsync(false, ct);
                    await ReconcileSnapshotAsync(ct);
                    reconciled = true;
                    continue;
                }
                if (batch.Reason == "retry_backoff")
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(batch.RetryAfterSeconds, 1, 30)), ct);
                    continue;
                }
                if (batch.Reason is not null) throw new System.Text.Json.JsonException("Unknown delivery state.");
                if (batch.Events.Count == 0)
                {
                    if (batch.DeliveryId is not null) throw new System.Text.Json.JsonException("Unexpected delivery identity.");
                    if (reconnect && !reconciled) { await ReconcileSnapshotAsync(ct); reconciled = true; continue; }
                    ct.ThrowIfCancellationRequested();
                    if (_disposed || generation != Volatile.Read(ref _generation)) throw new OperationCanceledException();
                    await _store.SetConnectedAsync(true, ct);
                    _connected = true;
                    // A concurrent Disconnect/Dispose must win even if it raced the durable state write.
                    if (_disposed || generation != Volatile.Read(ref _generation))
                    { _connected = false; await _store.SetConnectedAsync(false, CancellationToken.None); throw new OperationCanceledException(); }
                    return;
                }
                if (string.IsNullOrWhiteSpace(batch.DeliveryId)) throw new System.Text.Json.JsonException("Missing delivery identity.");
                AuthorizationConsumerApplyResult applied = await _store.ApplyAsync(batch.Events, ct);
                if (applied.RequiresSnapshot)
                {
                    _connected = false;
                    await _store.SetConnectedAsync(false, ct);
                    await ReconcileSnapshotAsync(ct);
                    reconciled = true;
                    continue;
                }
                if (!acknowledge) { _connected = false; await _store.SetConnectedAsync(false, ct); return; }
                await PostAsync("v1/authorization/ack", new AuthorizationConsumerAcknowledgment(batch.DeliveryId),
                    AuthorizationConsumerJsonContext.Default.AuthorizationConsumerAcknowledgment, ct);
            }
            throw new InvalidOperationException("Bounded replay exhausted; protected operations remain disabled.");
        }
        catch
        {
            _connected = false;
            Interlocked.Increment(ref _generation);
            await _store.SetConnectedAsync(false, CancellationToken.None);
            throw;
        }
        finally { _processing.Release(); }
    }

    /// <summary>
    /// Checks Aegir immediately before the protected operation. The caller must not cache a successful decision for another operation.
    /// Independent business effects remain the application's transaction; acknowledgment never proves those effects completed.
    /// </summary>
    /// <param name="humanAccessToken">A freshly authenticated organization/application-scoped human ticket.</param>
    /// <param name="operation">The protected operation's exact required permission.</param>
    /// <param name="ct">Cancels the check; cancellation never grants access.</param>
    public async ValueTask<AuthorizationProtectedDecision> AuthorizeProtectedOperationAsync(string humanAccessToken,
        string operation, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (operation is not ("read" or "write") || string.IsNullOrWhiteSpace(humanAccessToken) || humanAccessToken.Length > 512)
            return await DenyAsync("invalid_protected_operation", ct);
        if (!_connected) return await DenyAsync("event_reconciliation_required", ct);
        int generation = Volatile.Read(ref _generation);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        ct = linked.Token;
        try
        {
            using var request = Request(HttpMethod.Post, "v1/authorization/check");
            request.Content = JsonContent.Create(new AuthorizationConsumerCheckRequest(humanAccessToken, operation),
                AuthorizationConsumerJsonContext.Default.AuthorizationConsumerCheckRequest);
            using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode is not (System.Net.HttpStatusCode.OK or System.Net.HttpStatusCode.Forbidden))
            {
                _connected = false;
                await _store.SetConnectedAsync(false, ct);
                return await DenyAsync("authoritative_access_unavailable", ct);
            }
            AuthorizationProtectedDecision decision = (await ReadStrictAsync(response, AuthorizationConsumerJsonContext.Default.AuthorizationProtectedDecision, ct)) ?? throw new InvalidOperationException("Missing current access decision.");
            if (string.IsNullOrWhiteSpace(decision.Reason) || decision.AuthorizationEpoch < 0 ||
                decision.EffectiveGroupIds is null || decision.Permissions is null ||
                decision.EffectiveGroupIds.Count > 100 || decision.EffectiveGroupIds.Any(string.IsNullOrWhiteSpace) ||
                decision.Permissions.Any(x => x is not ("read" or "write")) ||
                decision.IsAuthorized && (response.StatusCode != System.Net.HttpStatusCode.OK || decision.Reason != "authorized" ||
                    string.IsNullOrWhiteSpace(decision.ApplicationSubjectId) || decision.EffectiveGroupIds.Count == 0 ||
                    !decision.Permissions.Contains(operation, StringComparer.Ordinal)) ||
                !decision.IsAuthorized && (response.StatusCode != System.Net.HttpStatusCode.Forbidden || decision.Reason == "authorized"))
            {
                _connected = false;
                await _store.SetConnectedAsync(false, ct);
                return await DenyAsync("invalid_authority_response", ct);
            }
            if (!decision.IsAuthorized)
            {
                if (decision.Reason == "event_reconciliation_required")
                {
                    _connected = false;
                    await _store.SetConnectedAsync(false, ct);
                }
                if (_onDenied is not null) await _onDenied(decision.Reason, ct);
            }
            if (_disposed || !_connected || generation != Volatile.Read(ref _generation))
                return await DenyAsync("event_reconciliation_required", CancellationToken.None);
            ct.ThrowIfCancellationRequested();
            return decision;
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or OperationCanceledException or InvalidOperationException)
        {
            _connected = false;
            await _store.SetConnectedAsync(false, CancellationToken.None);
            return await DenyAsync("authoritative_access_unavailable", CancellationToken.None);
        }
    }

    /// <summary>
    /// Invokes an application effect only after a fresh Aegir permit for this operation.
    /// Authorization linearizes at the server check; the later effect belongs to the application's
    /// own transaction. This does not create cross-database atomicity or arbitrary exactly-once effects.
    /// </summary>
    /// <param name="humanAccessToken">A freshly authenticated scoped human ticket.</param>
    /// <param name="operation">The exact permission required by this effect.</param>
    /// <param name="protectedEffect">Application code invoked once by this call only when currently permitted.</param>
    /// <param name="ct">Cancels the check or application effect without granting authority.</param>
    public async ValueTask<AuthorizationProtectedDecision> ExecuteProtectedOperationAsync(string humanAccessToken,
        string operation, Func<CancellationToken, ValueTask> protectedEffect, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(protectedEffect);
        AuthorizationProtectedDecision decision = await AuthorizeProtectedOperationAsync(humanAccessToken, operation, ct);
        if (decision.IsAuthorized) { ct.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(_disposed, this); await protectedEffect(ct); }
        return decision;
    }

    /// <summary>Checks before preparing an application transaction and again immediately before its commit callback.
    /// The caller owns rollback/disposal of preparation on denial. This narrows, but cannot eliminate, a cross-database revocation race.</summary>
    public async ValueTask<AuthorizationProtectedDecision> ExecuteRevalidatedOperationAsync(string humanAccessToken,
        string operation, Func<CancellationToken, ValueTask> prepare, Func<CancellationToken, ValueTask> commit,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(prepare); ArgumentNullException.ThrowIfNull(commit);
        AuthorizationProtectedDecision decision = await AuthorizeProtectedOperationAsync(humanAccessToken, operation, ct);
        if (!decision.IsAuthorized) return decision;
        ct.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(_disposed, this);
        await prepare(ct);
        decision = await AuthorizeProtectedOperationAsync(humanAccessToken, operation, ct);
        if (decision.IsAuthorized) { ct.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(_disposed, this); await commit(ct); }
        return decision;
    }

    /// <summary>Disables protected operations until a fresh successful reconnection.</summary>
    /// <param name="ct">Cancels persistence of the disconnected state.</param>
    public async ValueTask DisconnectAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Interlocked.Increment(ref _generation);
        _connected = false;
        await _store.SetConnectedAsync(false, ct);
    }

    /// <summary>Disables this instance and disposes its owned client; an injected test client remains caller-owned.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Interlocked.Increment(ref _generation);
        _connected = false;
        _lifetime.Cancel();
        if (_ownsHttpClient) _http.Dispose();
    }

    internal static AuthorizationEventReferenceConsumer CreateLoopbackForTests(Uri baseAddress, string credential,
        IAuthorizationEventConsumerStore store) => new(CreateOwnedClient(baseAddress, allowLoopbackHttpForTests: true, credential, store), credential, store)
        { _ownsHttpClient = true };

    /// <summary>Creates an isolated HTTPS loopback development consumer without modifying certificate trust stores.</summary>
    /// <param name="baseAddress">A clean HTTPS localhost or numeric loopback address ending in a slash.</param>
    /// <param name="credential">The application backend credential; never send it to a browser.</param>
    /// <param name="store">The integrating application's durable journal.</param>
    /// <param name="certificateSha256">The exact 64 hexadecimal character SHA256 of the staging certificate.</param>
    /// <remarks>Not a production deployment option. A different certificate, proxy, redirect or non-loopback address is rejected.</remarks>
    public static AuthorizationEventReferenceConsumer CreatePinnedLoopbackDevelopment(Uri baseAddress, string credential,
        IAuthorizationEventConsumerStore store, string certificateSha256)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        if (!baseAddress.IsAbsoluteUri || baseAddress.Scheme != Uri.UriSchemeHttps || !baseAddress.IsLoopback ||
            baseAddress.Host is not ("localhost" or "127.0.0.1" or "[::1]") ||
            !string.IsNullOrEmpty(baseAddress.UserInfo) || !string.IsNullOrEmpty(baseAddress.Query) ||
            !string.IsNullOrEmpty(baseAddress.Fragment) || !baseAddress.AbsolutePath.EndsWith("/", StringComparison.Ordinal))
            throw new ArgumentException("Pinned development transport requires a clean HTTPS loopback address.", nameof(baseAddress));
        if (certificateSha256 is null || certificateSha256.Length != 64 || certificateSha256.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("An exact SHA256 certificate pin is required.", nameof(certificateSha256));
        byte[] pin = Convert.FromHexString(certificateSha256);
        var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate is not null &&
            System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(pin,
                certificate.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256));
        var http = new HttpClient(handler) { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(15) };
        try { return new AuthorizationEventReferenceConsumer(http, credential, store) { _ownsHttpClient = true }; }
        catch { http.Dispose(); throw; }
    }

    private static HttpClient CreateOwnedClient(Uri baseAddress, bool allowLoopbackHttpForTests,
        string credential, IAuthorizationEventConsumerStore store)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(store);
        if (string.IsNullOrWhiteSpace(credential) || credential.Length > 512 || credential.Any(c => c < 33 || c > 126)) throw new ArgumentException("A bounded printable application backend credential is required.");
        if (!baseAddress.IsAbsoluteUri || !string.IsNullOrEmpty(baseAddress.UserInfo) || !string.IsNullOrEmpty(baseAddress.Query) ||
            !string.IsNullOrEmpty(baseAddress.Fragment) || !baseAddress.AbsolutePath.EndsWith("/", StringComparison.Ordinal) ||
            baseAddress.Scheme != Uri.UriSchemeHttps && !(allowLoopbackHttpForTests && baseAddress.Scheme == Uri.UriSchemeHttp && baseAddress.IsLoopback))
            throw new ArgumentException("A clean HTTPS deployment base address ending in a slash is required.", nameof(baseAddress));
        return new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false }) { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(15) };
    }

    private async ValueTask<AuthorizationNotificationBatch> GetBatchAsync(CancellationToken ct)
    {
        using var request = Request(HttpMethod.Get, "v1/authorization/events?limit=100");
        using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode(); // Preserve non-2xx HTTP exception compatibility; never follow redirects.
        if (response.StatusCode != System.Net.HttpStatusCode.OK) throw new JsonException("Invalid event status.");
        return (await ReadStrictAsync(response, AuthorizationConsumerJsonContext.Default.AuthorizationNotificationBatch, ct))
            ?? throw new InvalidOperationException("Missing authorization delivery batch.");
    }

    private async ValueTask ReconcileSnapshotAsync(CancellationToken ct)
    {
        using var request = Request(HttpMethod.Get, "v1/authorization/snapshot");
        using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        if (response.StatusCode != System.Net.HttpStatusCode.OK) throw new JsonException("Invalid snapshot status.");
        AuthorizationConsumerSnapshot snapshot = (await ReadStrictAsync(response, AuthorizationConsumerJsonContext.Default.AuthorizationConsumerSnapshot, ct)) ?? throw new InvalidOperationException("Missing snapshot.");
        await _store.ApplySnapshotAsync(snapshot, ct);
        await PostAsync("v1/authorization/snapshot/ack", new AuthorizationConsumerSnapshotAcknowledgment(snapshot.SnapshotId),
            AuthorizationConsumerJsonContext.Default.AuthorizationConsumerSnapshotAcknowledgment, ct);
    }

    private async ValueTask PostAsync<T>(string path, T body, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> metadata, CancellationToken ct)
    {
        using var request = Request(HttpMethod.Post, path);
        request.Content = JsonContent.Create(body, metadata);
        using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        if (response.StatusCode != System.Net.HttpStatusCode.NoContent) throw new JsonException("Invalid acknowledgment status.");
    }

    internal static async ValueTask<T?> ReadStrictAsync<T>(HttpResponseMessage response,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> metadata, CancellationToken ct)
    {
        if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new JsonException("JSON content type required.");
        if (response.Content.Headers.ContentLength > 2 * 1024 * 1024) throw new JsonException("Response exceeds bound.");
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var body = new MemoryStream(); byte[] buffer = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(buffer, ct)) != 0)
        {
            if (body.Length + count > 2 * 1024 * 1024) throw new JsonException("Response exceeds bound.");
            body.Write(buffer, 0, count);
        }
        using JsonDocument document = JsonDocument.Parse(body.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        RejectDuplicates(document.RootElement);
        return JsonSerializer.Deserialize(document.RootElement, metadata);
    }
    internal static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            { if (!names.Add(property.Name)) throw new JsonException("Duplicate JSON property."); RejectDuplicates(property.Value); }
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var value in element.EnumerateArray()) RejectDuplicates(value);
    }

    private HttpRequestMessage Request(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-Aegir-Application-Key", _credential);
        return request;
    }

    private async ValueTask<AuthorizationProtectedDecision> DenyAsync(string reason, CancellationToken ct)
    {
        if (_onDenied is not null) await _onDenied(reason, ct);
        return new(false, reason, null, 0, [], []);
    }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, PropertyNameCaseInsensitive = false)]
[JsonSerializable(typeof(AuthorizationNotificationBatch))]
[JsonSerializable(typeof(AuthorizationConsumerSnapshot))]
[JsonSerializable(typeof(AuthorizationProtectedDecision))]
[JsonSerializable(typeof(AuthorizationConsumerCheckRequest))]
[JsonSerializable(typeof(AuthorizationConsumerAcknowledgment))]
[JsonSerializable(typeof(AuthorizationConsumerSnapshotAcknowledgment))]
internal partial class AuthorizationConsumerJsonContext : JsonSerializerContext;
