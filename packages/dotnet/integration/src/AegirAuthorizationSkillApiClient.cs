// Copyright Foxlin Industries. Unreleased source-only C4 canonical authorization observation; no grant or mutation.
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record AuthorizationInspectionRequest(Guid OperationId, string SkillKey, string Version, string ManifestDigest,
    string AdapterDigest, string ResourceAlias, Guid ExpectedGrantId,string TargetPrincipalId,string Permission);
public sealed record AuthorizationPermissionInspection(string ResourceAlias,string Permission,string Decision,string Reason);
public sealed record AuthorizationInspectionResult(Guid OperationId, string Outcome, Guid GrantId, bool IsReplay,
    AuthorizationPermissionInspection? Inspection, string? ResultCommitment, string Delivery);
public sealed class AuthorizationSkillApiException(Guid operationId, bool requiresReconciliation, int? statusCode = null)
    : Exception(requiresReconciliation ? "Authorization inspection outcome uncertain; explicitly reconcile the original operation." : "Authorization inspection refused; values suppressed.")
{
    public Guid OperationId => operationId;
    public bool RequiresReconciliation => requiresReconciliation;
    public int? StatusCode => statusCode;
}

/// <summary>Exact installed reference/current Agent key and original consenting Human target. A current
/// canonical read/write decision is an observation, never future authority. No automatic retry.</summary>
public sealed class AegirAuthorizationSkillApiClient : IDisposable
{
    private readonly HttpClient http;
    private readonly string key, reference;
    public AegirAuthorizationSkillApiClient(Uri endpoint, string agentKey, string installedReference, string? loopbackCertificateSha256 = null)
    {
        if (!endpoint.IsAbsoluteUri || endpoint is not { Scheme: "https", UserInfo: "", Query: "", Fragment: "", AbsolutePath: "/" } ||
            string.IsNullOrEmpty(agentKey) || agentKey.Length > 2048 || agentKey.Any(char.IsControl) || !agentKey.Contains(':') ||
            installedReference is null || installedReference.Length != 69 || !installedReference.StartsWith("ags2_", StringComparison.Ordinal) || installedReference.AsSpan(5).ContainsAnyExcept("0123456789abcdef"))
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
    public override string ToString() => "AegirAuthorizationSkillApiClient { credentials = [redacted], operation = current authorization observation only }";
    public Task<AuthorizationInspectionResult> InspectAsync(AuthorizationInspectionRequest request, CancellationToken cancellationToken = default) => SendAsync(request, "execute", cancellationToken);
    public Task<AuthorizationInspectionResult> ReconcileAsync(AuthorizationInspectionRequest originalRequest, CancellationToken cancellationToken = default) => SendAsync(originalRequest, "status", cancellationToken);
    private async Task<AuthorizationInspectionResult> SendAsync(AuthorizationInspectionRequest request, string action, CancellationToken ct)
    {
        if (request is null || request.OperationId == Guid.Empty || request.ExpectedGrantId == Guid.Empty || !LowerHex(request.SkillKey) || !LowerHex(request.ManifestDigest) || !LowerHex(request.AdapterDigest) ||
            string.IsNullOrEmpty(request.Version) || request.Version.Length > 64 || request.Version.Any(char.IsControl) || string.IsNullOrEmpty(request.ResourceAlias) || request.ResourceAlias.Length > 160 || request.ResourceAlias.Any(char.IsControl) || !Identifier(request.TargetPrincipalId) || request.Permission is not("read"or"write"))
            throw new ArgumentException("Invalid bounded authorization inspection request; values suppressed.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30)); var stop = deadline.Token;
        using var message = new HttpRequestMessage(HttpMethod.Post, "/v1/skills/v2/authorization-inspection") { Content = JsonContent.Create(new
        { action, operationId = request.OperationId.ToString("N"), skillKey = request.SkillKey, skillVersion = request.Version, manifestDigest = request.ManifestDigest, adapterDigest = request.AdapterDigest,
            resourcePolicy = "application.group.authorization-inspection.read", resourceAlias = request.ResourceAlias, scope = "security:read", operation = "application.group.authorization.inspect",targetPrincipalId=request.TargetPrincipalId,permission=request.Permission }) };
        message.Headers.Add("X-Aegir-Agent-Key", key); message.Headers.Add("X-Aegir-Delegation", reference); message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, stop);
            if (!response.IsSuccessStatusCode) throw new AuthorizationSkillApiException(request.OperationId, (int)response.StatusCode >= 500 || (int)response.StatusCode is >= 300 and < 400 or 408 or 499, (int)response.StatusCode);
            if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new JsonException();
            using var stream = await response.Content.ReadAsStreamAsync(stop); using var bytes = new MemoryStream(); byte[] buffer = new byte[2048]; int n;
            while ((n = await stream.ReadAsync(buffer, stop)) > 0) { if (bytes.Length + n > 16384) throw new JsonException(); bytes.Write(buffer, 0, n); }
            using var doc = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 5 }); var root = doc.RootElement; Shape(root, "schema", "result");
            if (Text(root, "schema") != "aegir.authorization-skill.execution/v1") throw new JsonException();
            var r = root.GetProperty("result"); Shape(r, "outcome", "executionId", "grantId", "isReplay", "metadata", "resultDigest", "delivery");
            if (Text(r, "executionId") != request.OperationId.ToString("N") || Text(r, "grantId") != request.ExpectedGrantId.ToString("N")) throw new JsonException();
            string outcome = Text(r, "outcome"), delivery = Text(r, "delivery"); bool replay = r.GetProperty("isReplay").GetBoolean();
            if (outcome is not ("ExecutedAuthorizationInspection" or "AlreadyConsumed" or "CommittedRead" or "Unknown/recovery-required" or "Expired" or "Suspended" or "Revoked" or "UseLimitExhausted")) throw new JsonException();
            if (action == "status" && (outcome is not ("CommittedRead" or "Unknown/recovery-required") || !replay) || action == "execute" && outcome is ("CommittedRead" or "Unknown/recovery-required")) throw new JsonException();
            if (delivery is not ("response_prepared_client_receipt_unproven" or "client_receipt_unproven")) throw new JsonException();
            string? commitment = r.GetProperty("resultDigest").ValueKind == JsonValueKind.Null ? null : Text(r, "resultDigest");
            if (commitment is not null && !LowerHex(commitment)) throw new JsonException();
            if (outcome == "AlreadyConsumed" && !replay || outcome is not ("ExecutedAuthorizationInspection" or "CommittedRead") && commitment is not null) throw new JsonException();
            AuthorizationPermissionInspection? inspection = null; var m = r.GetProperty("metadata");
            if (outcome == "ExecutedAuthorizationInspection")
            {
                if (replay || commitment is null || action != "execute") throw new JsonException();
                Shape(m,"schema","resourceAlias","operation","principalScope","permission","decision","reason","authority","observationOnly","authorityGranted");
                string permission=Text(m,"permission"),decision=Text(m,"decision"),reason=Text(m,"reason");
                if(Text(m,"schema")!="aegir.skill.authorization-inspection-output/v1"||Text(m,"resourceAlias")!=request.ResourceAlias||
                    Text(m,"operation")!="application.group.authorization.inspect"||Text(m,"principalScope")!="consenting-human-only"||
                    Text(m,"authority")!="canonical-current-engine"||permission!=request.Permission||!m.GetProperty("observationOnly").GetBoolean()||m.GetProperty("authorityGranted").GetBoolean()||
                    !ValidDecision(decision,reason))throw new JsonException();
                inspection=new(request.ResourceAlias,permission,decision,reason);
            }
            else if (m.ValueKind != JsonValueKind.Null || outcome == "CommittedRead" && commitment is null) throw new JsonException();
            return new(request.OperationId, outcome, request.ExpectedGrantId, replay, inspection, commitment, delivery);
        }
        catch (AuthorizationSkillApiException) { throw; }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        { throw new AuthorizationSkillApiException(request.OperationId, true); }
    }
    private static bool Identifier(string? s)=>s is{Length:>=1 and <=128}&&s.All(c=>char.IsAsciiLetterOrDigit(c)||c is '_'or'-'or'.'or':');
    private static bool ValidDecision(string decision,string reason)=>(decision,reason) switch
    {("Allowed","permission_granted")=>true,("Denied","permission_not_granted"or"license_required"or"group_access_required"or"resource_not_current")=>true,
     ("Unsupported","single_group_profile_required")=>true,("Indeterminate","canonical_state_unverifiable")=>true,_=>false};
    private static bool Hex(string s) => s is{Length:64} && s.All(char.IsAsciiHexDigit);
    private static bool LowerHex(string s) => Hex(s) && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string Text(JsonElement r, string name) => r.GetProperty(name).ValueKind == JsonValueKind.String ? r.GetProperty(name).GetString()! : throw new JsonException();
    private static void Shape(JsonElement r, params string[] names)
    {
        if (r.ValueKind != JsonValueKind.Object) throw new JsonException(); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in r.EnumerateObject()) if (!names.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) throw new JsonException();
        if (seen.Count != names.Length) throw new JsonException();
    }
}
