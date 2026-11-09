// Copyright Foxlin Industries. Unreleased source integration; no package publication.
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Foxlin.Aegir.Auth.AuthorizationEvents;

/// <summary>Supported one-organization/application integration settings. Secrets belong on the application backend.</summary>
public sealed record AegirIntegrationOptions(Uri ApiBaseUrl, Uri WebBaseUrl, string OrganizationId, string ApplicationId,
    string ApplicationCredential, string? LoopbackCertificateSha256 = null)
{
    /// <summary>Never exposes credential contents through ordinary diagnostics.</summary>
    public override string ToString() => "AegirIntegrationOptions { credentials = [redacted] }";
}
/// <summary>Authentication result. The opaque human ticket stays in this client, never in the event journal.</summary>
public sealed record AegirIntegrationAuthentication(bool Authenticated, bool MfaRequired, string? ChallengeId, string Reason);

/// <summary>Backend-owned typed integration over the genuine canonical HTTP consumer. No event, local journal or old group claim grants access.</summary>
public sealed class AegirIntegrationClient : IDisposable
{
    private readonly AegirIntegrationOptions _options;
    private readonly HttpClient _authentication;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _authLock = new(1, 1);
    private string? _ticket;
    private bool _disposed;
    /// <summary>The genuine event consumer; caller retains ownership of its journal.</summary>
    public AuthorizationEventReferenceConsumer Events { get; }

    /// <summary>Creates isolated, non-redirecting HTTPS transports. Certificate pin is allowed only for explicit local development.</summary>
    public AegirIntegrationClient(AegirIntegrationOptions options, IAuthorizationEventConsumerStore journal)
    {
        ArgumentNullException.ThrowIfNull(options); ArgumentNullException.ThrowIfNull(journal);
        if (string.IsNullOrWhiteSpace(options.OrganizationId) || string.IsNullOrWhiteSpace(options.ApplicationId)) throw new ArgumentException("Organization/application required.");
        _options = options;
        _authentication = CreateAuthenticationClient(options.WebBaseUrl, options.LoopbackCertificateSha256);
        try
        {
            Events = options.LoopbackCertificateSha256 is null
                ? new(options.ApiBaseUrl, options.ApplicationCredential, journal)
                : AuthorizationEventReferenceConsumer.CreatePinnedLoopbackDevelopment(options.ApiBaseUrl, options.ApplicationCredential, journal, options.LoopbackCertificateSha256);
        }
        catch { _authentication.Dispose(); throw; }
    }

    /// <summary>Uses real password/MFA contracts. A failed attempt clears the old ticket; regrant never silently reauthenticates.</summary>
    public async ValueTask<AegirIntegrationAuthentication> AuthenticateAsync(string username, string password,
        string? challengeId = null, string? totpCode = null, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        ct = linked.Token;
        await _authLock.WaitAsync(ct);
        try
        {
            _ticket = null;
            using var request = new HttpRequestMessage(HttpMethod.Post, "account/organization-access")
            { Content = JsonContent.Create(new IntegrationLogin(username, password, _options.OrganizationId, _options.ApplicationId, challengeId, totpCode), IntegrationJsonContext.Default.IntegrationLogin) };
            using var response = await _authentication.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                var error = await AuthorizationEventReferenceConsumer.ReadStrictAsync(response, IntegrationJsonContext.Default.IntegrationLoginError, ct);
                return new(false, error?.Error == "mfa_required", error?.ChallengeId, error?.Error ?? "authentication_denied");
            }
            if (response.StatusCode != HttpStatusCode.OK) return new(false, false, null, "authentication_denied");
            var login = await AuthorizationEventReferenceConsumer.ReadStrictAsync(response, IntegrationJsonContext.Default.IntegrationSession, ct);
            if (login is null || string.IsNullOrWhiteSpace(login.AccessToken) || login.AccessToken.Length != 64 ||
                string.IsNullOrWhiteSpace(login.SubjectId) || login.AuthorizationEpoch < 0 || login.OrganizationId != _options.OrganizationId || login.ApplicationId != _options.ApplicationId || login.ExpiresAtUtc <= DateTimeOffset.UtcNow)
                return new(false, false, null, "invalid_authentication_response");
            ObjectDisposedException.ThrowIf(_disposed, this); ct.ThrowIfCancellationRequested();
            _ticket = login.AccessToken;
            return new(true, false, null, "authenticated");
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or OperationCanceledException)
        { _ticket = null; return new(false, false, null, "authentication_unavailable"); }
        finally { _authLock.Release(); }
    }

    /// <summary>Fresh server-side read/write check. This never returns an offline permit.</summary>
    public ValueTask<AuthorizationProtectedDecision> AuthorizeAsync(string operation, CancellationToken ct = default)
    { ObjectDisposedException.ThrowIf(_disposed, this); return Events.AuthorizeProtectedOperationAsync(_ticket ?? "", operation, ct); }
    /// <summary>Checks immediately before the callback; side effects belong to the application's transaction.</summary>
    public ValueTask<AuthorizationProtectedDecision> ExecuteAsync(string operation, Func<CancellationToken, ValueTask> effect, CancellationToken ct = default)
    { ObjectDisposedException.ThrowIf(_disposed, this); return Events.ExecuteProtectedOperationAsync(_ticket ?? "", operation, effect, ct); }
    /// <summary>Checks before preparation and immediately before commit; the application must roll back uncommitted preparation on denial.</summary>
    public ValueTask<AuthorizationProtectedDecision> ExecuteRevalidatedAsync(string operation, Func<CancellationToken, ValueTask> prepare,
        Func<CancellationToken, ValueTask> commit, CancellationToken ct = default)
    { ObjectDisposedException.ThrowIf(_disposed, this); return Events.ExecuteRevalidatedOperationAsync(_ticket ?? "", operation, prepare, commit, ct); }
    /// <summary>Cancels outstanding network operations, forgets the ticket and closes owned transports.</summary>
    public void Dispose()
    {
        if (_disposed) return; _disposed = true; _ticket = null; _lifetime.Cancel(); Events.Dispose(); _authentication.Dispose();
    }
    private static HttpClient CreateAuthenticationClient(Uri uri, string? pin)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != "https" || !uri.AbsolutePath.EndsWith('/') || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new ArgumentException("A clean HTTPS base URL ending with slash is required.");
        var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
        if (pin is not null)
        {
            if (!uri.IsLoopback || uri.Host is not ("localhost" or "127.0.0.1" or "[::1]") || pin.Length != 64 || pin.Any(c => !Uri.IsHexDigit(c)))
            { handler.Dispose(); throw new ArgumentException("Development pin requires HTTPS loopback and exact SHA256."); }
            byte[] expected = Convert.FromHexString(pin);
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert is not null && CryptographicOperations.FixedTimeEquals(expected, cert.GetCertHash(HashAlgorithmName.SHA256));
        }
        return new(handler) { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(15) };
    }
}
internal sealed record IntegrationLogin(string Username, string Password, string OrganizationId, string ApplicationId, string? ChallengeId, string? TotpCode);
internal sealed record IntegrationLoginError(string Error, string? ChallengeId);
internal sealed record IntegrationSession([property: JsonRequired] string AccessToken, [property: JsonRequired] DateTimeOffset ExpiresAtUtc,
    [property: JsonRequired] string OrganizationId, [property: JsonRequired] string ApplicationId,
    [property: JsonRequired] string SubjectId, [property: JsonRequired] long AuthorizationEpoch);
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(IntegrationLogin))]
[JsonSerializable(typeof(IntegrationLoginError))]
[JsonSerializable(typeof(IntegrationSession))]
internal partial class IntegrationJsonContext : JsonSerializerContext;
