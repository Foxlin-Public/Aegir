// Copyright Foxlin Industries. Unreleased source-only C3 API consumer; no MCP authentication tool or ceremony.
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record AuthenticationInspectionRequest(Guid OperationId, string SkillKey, string Version, string ManifestDigest,
    string AdapterDigest, string ResourceAlias, Guid ExpectedGrantId);
public sealed record AuthenticationConfigurationInspection(string ResourceAlias, string ReturnUriConfiguration,
    int InspectedEntryCount, int UsableAllowedReturnUriCount);
public sealed record AuthenticationInspectionResult(Guid OperationId, string Outcome, Guid GrantId, bool IsReplay,
    AuthenticationConfigurationInspection? Inspection, string? ResultCommitment, string Delivery);
public sealed class AuthenticationSkillApiException(Guid operationId, bool requiresReconciliation, int? statusCode = null)
    : Exception(requiresReconciliation ? "Authentication inspection outcome uncertain; explicitly reconcile the original operation." : "Authentication inspection refused; values suppressed.")
{
    public Guid OperationId => operationId;
    public bool RequiresReconciliation => requiresReconciliation;
    public int? StatusCode => statusCode;
}

/// <summary>Exact installed reference, current Agent key and application API host. Read-only configuration inspection;
/// does not authenticate a Human, start a ceremony or certify an integration. Never automatically retries.</summary>
public sealed class AegirAuthenticationSkillApiClient : IDisposable
{
    private readonly HttpClient http;
    private readonly string key, reference;
    public AegirAuthenticationSkillApiClient(Uri endpoint, string agentKey, string installedReference, string? loopbackCertificateSha256 = null)
    {
        if (!endpoint.IsAbsoluteUri || endpoint is not { Scheme: "https", UserInfo: "", Query: "", Fragment: "", AbsolutePath: "/" } ||
            string.IsNullOrEmpty(agentKey) || agentKey.Length > 2048 || agentKey.Any(char.IsControl) || !agentKey.Contains(':') ||
            installedReference.Length != 69 || !installedReference.StartsWith("ags2_", StringComparison.Ordinal) || installedReference.AsSpan(5).ContainsAnyExcept("0123456789abcdef"))
            throw new ArgumentException("Explicit HTTPS Agent and installed Skill context required; values suppressed.");
        var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
        if (loopbackCertificateSha256 is not null)
        {
            if (!endpoint.IsLoopback || !Hex(loopbackCertificateSha256)) throw new ArgumentException("Explicit loopback certificate pin required.");
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) => certificate is not null &&
                string.Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256), loopbackCertificateSha256, StringComparison.OrdinalIgnoreCase) &&
                (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 && certificate.NotBefore.ToUniversalTime() <= DateTime.UtcNow && certificate.NotAfter.ToUniversalTime() >= DateTime.UtcNow;
        }
        http = new HttpClient(handler) { BaseAddress = endpoint, Timeout = TimeSpan.FromSeconds(30) }; key = agentKey; reference = installedReference;
    }
    public void Dispose() => http.Dispose();
    public override string ToString() => "AegirAuthenticationSkillApiClient { credentials = [redacted], operation = configuration inspection only }";
    public Task<AuthenticationInspectionResult> InspectAsync(AuthenticationInspectionRequest request, CancellationToken cancellationToken = default) => SendAsync(request, "execute", cancellationToken);
    public Task<AuthenticationInspectionResult> ReconcileAsync(AuthenticationInspectionRequest originalRequest, CancellationToken cancellationToken = default) => SendAsync(originalRequest, "status", cancellationToken);
    private async Task<AuthenticationInspectionResult> SendAsync(AuthenticationInspectionRequest request, string action, CancellationToken ct)
    {
        if (request.OperationId == Guid.Empty || request.ExpectedGrantId == Guid.Empty || !LowerHex(request.SkillKey) || !LowerHex(request.ManifestDigest) || !LowerHex(request.AdapterDigest) ||
            request.Version.Length is < 1 or > 64 || request.Version.Any(char.IsControl) || request.ResourceAlias.Length is < 1 or > 160 || request.ResourceAlias.Any(char.IsControl))
            throw new ArgumentException("Invalid bounded authentication inspection request; values suppressed.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30)); var stop = deadline.Token;
        using var message = new HttpRequestMessage(HttpMethod.Post, "/v1/skills/v2/authentication-integration") { Content = JsonContent.Create(new
        { action, operationId = request.OperationId.ToString("N"), skillKey = request.SkillKey, skillVersion = request.Version, manifestDigest = request.ManifestDigest, adapterDigest = request.AdapterDigest,
            resourcePolicy = "application.authentication.integration.read", resourceAlias = request.ResourceAlias, scope = "security:read", operation = "application.authentication.integration.inspect" }) };
        message.Headers.Add("X-Aegir-Agent-Key", key); message.Headers.Add("X-Aegir-Delegation", reference); message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, stop);
            if (!response.IsSuccessStatusCode) throw new AuthenticationSkillApiException(request.OperationId, (int)response.StatusCode >= 500 || (int)response.StatusCode is >= 300 and < 400 or 408 or 499, (int)response.StatusCode);
            if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new JsonException();
            using var stream = await response.Content.ReadAsStreamAsync(stop); using var bytes = new MemoryStream(); byte[] buffer = new byte[2048]; int n;
            while ((n = await stream.ReadAsync(buffer, stop)) > 0) { if (bytes.Length + n > 16384) throw new JsonException(); bytes.Write(buffer, 0, n); }
            using var doc = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 5 }); var root = doc.RootElement; Shape(root, "schema", "result");
            if (Text(root, "schema") != "aegir.authentication-skill.execution/v1") throw new JsonException();
            var r = root.GetProperty("result"); Shape(r, "outcome", "executionId", "grantId", "isReplay", "metadata", "resultDigest", "delivery");
            if (Text(r, "executionId") != request.OperationId.ToString("N") || Text(r, "grantId") != request.ExpectedGrantId.ToString("N")) throw new JsonException();
            string outcome = Text(r, "outcome"), delivery = Text(r, "delivery"); bool replay = r.GetProperty("isReplay").GetBoolean();
            if (outcome is not ("ExecutedAuthenticationInspection" or "AlreadyConsumed" or "CommittedRead" or "Unknown/recovery-required" or "Expired" or "Suspended" or "Revoked" or "UseLimitExhausted")) throw new JsonException();
            if (action == "status" && (outcome is not ("CommittedRead" or "Unknown/recovery-required") || !replay) || action == "execute" && outcome is ("CommittedRead" or "Unknown/recovery-required")) throw new JsonException();
            if (delivery is not ("response_prepared_client_receipt_unproven" or "client_receipt_unproven")) throw new JsonException();
            string? commitment = r.GetProperty("resultDigest").ValueKind == JsonValueKind.Null ? null : Text(r, "resultDigest");
            if (commitment is not null && !LowerHex(commitment)) throw new JsonException();
            if (outcome == "AlreadyConsumed" && !replay || outcome is not ("ExecutedAuthenticationInspection" or "CommittedRead") && commitment is not null) throw new JsonException();
            AuthenticationConfigurationInspection? inspection = null; var m = r.GetProperty("metadata");
            if (outcome == "ExecutedAuthenticationInspection")
            {
                if (replay || commitment is null || action != "execute") throw new JsonException();
                Shape(m, "schema", "resourceAlias", "operation", "configurationAuthority", "returnUriConfiguration", "inspectedEntryCount", "usableAllowedReturnUriCount", "ceremonyExecuted", "authenticationEstablished");
                string state = Text(m, "returnUriConfiguration"); int count = m.GetProperty("inspectedEntryCount").GetInt32(), usable = m.GetProperty("usableAllowedReturnUriCount").GetInt32();
                if (Text(m, "schema") != "aegir.skill.authentication-inspection-output/v1" || Text(m, "resourceAlias") != request.ResourceAlias || Text(m, "operation") != "application.authentication.integration.inspect" ||
                    Text(m, "configurationAuthority") != "executing-api-host" || m.GetProperty("ceremonyExecuted").GetBoolean() || m.GetProperty("authenticationEstablished").GetBoolean() ||
                    count is < 0 or > 16 || usable < 0 || usable > count || state is not ("missing" or "configured" or "contains-invalid-entries" or "inspection-limit-exceeded")) throw new JsonException();
                if (state is ("missing" or "inspection-limit-exceeded") && (count != 0 || usable != 0) ||
                    state == "configured" && (count < 1 || usable != count) || state == "contains-invalid-entries" && (count < 1 || usable == count)) throw new JsonException();
                inspection = new(request.ResourceAlias, state, count, usable);
            }
            else if (m.ValueKind != JsonValueKind.Null || outcome == "CommittedRead" && commitment is null) throw new JsonException();
            return new(request.OperationId, outcome, request.ExpectedGrantId, replay, inspection, commitment, delivery);
        }
        catch (AuthenticationSkillApiException) { throw; }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        { throw new AuthenticationSkillApiException(request.OperationId, true); }
    }
    private static bool Hex(string s) => s.Length == 64 && s.All(char.IsAsciiHexDigit);
    private static bool LowerHex(string s) => Hex(s) && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Text(JsonElement r, string name) => r.GetProperty(name).ValueKind == JsonValueKind.String ? r.GetProperty(name).GetString()! : throw new JsonException();
    private static void Shape(JsonElement r, params string[] names)
    {
        if (r.ValueKind != JsonValueKind.Object) throw new JsonException(); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in r.EnumerateObject()) if (!names.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) throw new JsonException();
        if (seen.Count != names.Length) throw new JsonException();
    }
}
