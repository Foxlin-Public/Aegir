// Copyright Foxlin Industries. Local single-writer adapter; events never grant access.
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Foxlin.Aegir.Auth.AuthorizationEvents;

/// <summary>Single-process durable invalidation journal. Owns an OS lock until disposed.
/// Atomic replacement commits receipts, versions and effects together. A restored journal still needs server reconciliation.
/// Host must secure the directory and handle disk failures; arbitrary business effects are outside this transaction.</summary>
public sealed class FileAuthorizationEventConsumerStore : IAuthorizationEventConsumerStore, IDisposable
{
    private readonly string _path;
    private readonly FileStream _lock;
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private bool _disposed;
    private FileConsumerState _state;
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    { "granted", "revoked", "adminGranted", "adminRevoked", "permissionChanged", "licenseGranted", "licenseRevoked", "membershipChanged", "suspended", "restored", "groupPolicyChanged" };

    /// <summary>Opens a journal under a caller-owned private directory. No credentials are persisted.</summary>
    public FileAuthorizationEventConsumerStore(string path, string scopeBinding)
    {
        if (string.IsNullOrWhiteSpace(scopeBinding) || scopeBinding.Length > 512) throw new ArgumentException("A stable API/organization/application binding is required.");
        _path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        _lock = new FileStream(_path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            if (File.Exists(_path) && new FileInfo(_path).Length > 16 * 1024 * 1024) throw new InvalidDataException("Journal exceeds bound.");
            if (File.Exists(_path))
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(_path), new JsonDocumentOptions { MaxDepth = 32 });
                AuthorizationEventReferenceConsumer.RejectDuplicates(document.RootElement);
                _state = JsonSerializer.Deserialize(document.RootElement, FileConsumerJsonContext.Default.FileConsumerState) ?? throw new InvalidDataException("Invalid journal.");
            }
            else _state = new() { Binding = scopeBinding };
            ValidateState(_state);
            if (_state.Binding != scopeBinding) throw new InvalidDataException("Journal belongs to another application scope.");
            _state.Connected = false; // persisted 'true' is never trusted on restart
            Save(_state);
        }
        catch { _lock.Dispose(); throw; }
    }

    /// <summary>Counts committed invalidation effects, without exposing credentials or human identities.</summary>
    public int EffectCount => _state.Effects.Count;
    /// <summary>Counts event receipts, including stale deliveries.</summary>
    public int ReceiptCount => _state.Receipts.Count;
    /// <summary>Copies monotonic application-specific group versions for diagnostics.</summary>
    public IReadOnlyDictionary<string, long> Versions => new Dictionary<string, long>(_state.Versions);

    /// <inheritdoc />
    public async ValueTask<AuthorizationConsumerApplyResult> ApplyAsync(IReadOnlyList<AuthorizationNotification> events, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (events is null || events.Count > 100) throw new ArgumentException("Bounded events required.");
        await _mutex.WaitAsync(ct);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            FileConsumerState next = Clone(); int effects = 0;
            foreach (var item in events)
            {
                if (item.ProtocolVersion != 1 || !Known.Contains(item.EventType) || item.GroupVersion < 1 ||
                    !Id(item.EventId) || !Id(item.TransactionId) || !Id(item.GroupId) || item.UserId is not null && !Id(item.UserId))
                    return new(0, true);
                string digest = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(item, FileConsumerJsonContext.Default.AuthorizationNotification)));
                if (next.Receipts.TryGetValue(item.EventId, out string? seen))
                { if (seen != digest) throw new InvalidDataException("Conflicting event identity."); continue; }
                long prior = next.Versions.GetValueOrDefault(item.GroupId);
                if (item.GroupVersion > prior + 1) return new(0, true);
                next.Receipts.Add(item.EventId, digest);
                if (item.GroupVersion < prior) continue;
                next.Versions[item.GroupId] = item.GroupVersion;
                next.Effects.Add(item.EventId); effects++;
            }
            if (next.Receipts.Count > 20000) throw new InvalidDataException("Journal retention bound requires operator checkpoint.");
            ct.ThrowIfCancellationRequested(); Save(next); _state = next;
            return new(effects, false);
        }
        finally { _mutex.Release(); }
    }

    /// <inheritdoc />
    public async ValueTask ApplySnapshotAsync(AuthorizationConsumerSnapshot snapshot, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (snapshot is null || !Id(snapshot.SnapshotId) || snapshot.Groups is null || snapshot.Groups.Count > 100 ||
            snapshot.Groups.Any(x => x.Subjects is null) || snapshot.Groups.Sum(x => x.Subjects.Count) > 2000)
            throw new InvalidDataException("Invalid snapshot.");
        await _mutex.WaitAsync(ct);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            FileConsumerState next = Clone(); var incoming = new Dictionary<string, long>(StringComparer.Ordinal);
            foreach (var group in snapshot.Groups)
            {
                if (!Id(group.GroupId) || group.GroupVersion < next.Versions.GetValueOrDefault(group.GroupId) || group.GroupVersion < 0 ||
                    !incoming.TryAdd(group.GroupId, group.GroupVersion) || group.Subjects.Any(x => !Id(x.UserId) || x.AuthorizationEpoch < 0) || group.Subjects.Select(x => x.UserId).Distinct(StringComparer.Ordinal).Count() != group.Subjects.Count)
                    throw new InvalidDataException("Invalid or rolled-back snapshot.");
            }
            // Keep high watermarks for absent groups too; a reintroduced group cannot rewind its journal.
            foreach (var pair in incoming) next.Versions[pair.Key] = pair.Value;
            ct.ThrowIfCancellationRequested(); Save(next); _state = next;
        }
        finally { _mutex.Release(); }
    }

    /// <inheritdoc />
    public async ValueTask SetConnectedAsync(bool connected, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _mutex.WaitAsync(ct);
        try { ObjectDisposedException.ThrowIf(_disposed, this); var next = Clone(); next.Connected = connected; ct.ThrowIfCancellationRequested(); Save(next); _state = next; }
        finally { _mutex.Release(); }
    }

    /// <summary>Releases the exclusive journal lease. A new instance always starts disconnected.</summary>
    public void Dispose()
    {
        _mutex.Wait();
        try { if (!_disposed) { _disposed = true; _lock.Dispose(); } }
        finally { _mutex.Release(); }
    }
    private FileConsumerState Clone() => new() { Binding = _state.Binding, Connected = _state.Connected, Receipts = new(_state.Receipts), Versions = new(_state.Versions), Effects = new(_state.Effects) };
    private static bool Id(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 256;
    private static void ValidateState(FileConsumerState value)
    {
        if (value.Version != 1 || value.Receipts is null || value.Effects is null || value.Versions is null ||
            value.Receipts.Count > 20000 || value.Versions.Count > 1000 || value.Versions.Any(x => !Id(x.Key) || x.Value < 0) ||
            value.Receipts.Any(x => !Id(x.Key) || x.Value is null || x.Value.Length != 64) || value.Effects.Any(x => !value.Receipts.ContainsKey(x)))
            throw new InvalidDataException("Invalid persisted journal.");
    }
    private void Save(FileConsumerState state)
    {
        string temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { JsonSerializer.Serialize(stream, state, FileConsumerJsonContext.Default.FileConsumerState); stream.Flush(true); }
            File.Move(temporary, _path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}

internal sealed class FileConsumerState
{
    [JsonRequired] public string Binding { get; set; } = "";
    [JsonRequired] public int Version { get; set; } = 1;
    [JsonRequired] public bool Connected { get; set; }
    [JsonRequired] public Dictionary<string, string> Receipts { get; set; } = new(StringComparer.Ordinal);
    [JsonRequired] public Dictionary<string, long> Versions { get; set; } = new(StringComparer.Ordinal);
    [JsonRequired] public HashSet<string> Effects { get; set; } = new(StringComparer.Ordinal);
}
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(FileConsumerState))]
[JsonSerializable(typeof(AuthorizationNotification))]
internal partial class FileConsumerJsonContext : JsonSerializerContext;
