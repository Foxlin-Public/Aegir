// Copyright Foxlin Industries. Unreleased source-only C5 bounded MCP contract inspection; never a tool-execution grant.
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record McpSecurityInspectionRequest(Guid OperationId, string SkillKey, string Version, string ManifestDigest,
    string AdapterDigest, string ResourceAlias, Guid ExpectedGrantId,string Tool);
public sealed record McpSecurityInspection(string ResourceAlias,string? Tool,string Decision,string? RequiredScope,string? CallerCategory,string? ContractDigest,string? InputSchemaDigest,string[] RequiredInputs,string StdioStatus,long ObservedAt);
public sealed record McpSecurityInspectionResult(Guid OperationId, string Outcome, Guid GrantId, bool IsReplay,
    McpSecurityInspection? Inspection, string? ResultCommitment, string Delivery);
public sealed class McpSecuritySkillApiException(Guid operationId, bool requiresReconciliation, int? statusCode = null)
    : Exception(requiresReconciliation ? "MCP security inspection outcome uncertain; explicitly reconcile the original operation." : "MCP security inspection refused; values suppressed.")
{
    public Guid OperationId => operationId;
    public bool RequiresReconciliation => requiresReconciliation;
    public int? StatusCode => statusCode;
}

/// <summary>Exact installed reference/current Agent key and consented MCP tool contract.
/// An inspection result is an observation, never execution authority. No automatic retry.</summary>
public sealed class AegirMcpSecuritySkillApiClient : IDisposable
{
    private readonly HttpClient http;
    private readonly string key, reference;
    public AegirMcpSecuritySkillApiClient(Uri endpoint, string agentKey, string installedReference, string? loopbackCertificateSha256 = null)
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
    public override string ToString() => "AegirMcpSecuritySkillApiClient { credentials = [redacted], operation = MCP contract observation only }";
    public Task<McpSecurityInspectionResult> InspectAsync(McpSecurityInspectionRequest request, CancellationToken cancellationToken = default) => SendAsync(request, "execute", cancellationToken);
    public Task<McpSecurityInspectionResult> ReconcileAsync(McpSecurityInspectionRequest originalRequest, CancellationToken cancellationToken = default) => SendAsync(originalRequest, "status", cancellationToken);
    private async Task<McpSecurityInspectionResult> SendAsync(McpSecurityInspectionRequest request, string action, CancellationToken ct)
    {
        if (request is null || request.OperationId == Guid.Empty || request.ExpectedGrantId == Guid.Empty || !LowerHex(request.SkillKey) || !LowerHex(request.ManifestDigest) || !LowerHex(request.AdapterDigest) ||
            string.IsNullOrEmpty(request.Version) || request.Version.Length > 64 || request.Version.Any(char.IsControl) || string.IsNullOrEmpty(request.ResourceAlias) || request.ResourceAlias.Length > 160 || request.ResourceAlias.Any(char.IsControl) || !ToolName(request.Tool))
            throw new ArgumentException("Invalid bounded MCP security inspection request; values suppressed.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30)); var stop = deadline.Token;
        using var message = new HttpRequestMessage(HttpMethod.Post, "/v1/skills/v2/mcp-security-inspection") { Content = JsonContent.Create(new
        { action, operationId = request.OperationId.ToString("N"), skillKey = request.SkillKey, skillVersion = request.Version, manifestDigest = request.ManifestDigest, adapterDigest = request.AdapterDigest,
            resourcePolicy = "application.mcp.security-inspection.read", resourceAlias = request.ResourceAlias, scope = "security:read", operation = "application.mcp.security.inspect",tool=request.Tool,integration="aegir.managed-http.v1",transportProfile="aegir-custom-http-jsonrpc",contractVersion="aegir.mcp.security-contract/v1" }) };
        message.Headers.Add("X-Aegir-Agent-Key", key); message.Headers.Add("X-Aegir-Delegation", reference); message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, stop);
            if (!response.IsSuccessStatusCode) throw new McpSecuritySkillApiException(request.OperationId, (int)response.StatusCode >= 500 || (int)response.StatusCode is >= 300 and < 400 or 408 or 499, (int)response.StatusCode);
            if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new JsonException();
            using var stream = await response.Content.ReadAsStreamAsync(stop); using var bytes = new MemoryStream(); byte[] buffer = new byte[2048]; int n;
            while ((n = await stream.ReadAsync(buffer, stop)) > 0) { if (bytes.Length + n > 16384) throw new JsonException(); bytes.Write(buffer, 0, n); }
            using var doc = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 5 }); var root = doc.RootElement; Shape(root, "schema", "result");
            if (Text(root, "schema") != "aegir.mcp-security-skill.execution/v1") throw new JsonException();
            var r = root.GetProperty("result"); Shape(r, "outcome", "executionId", "grantId", "isReplay", "metadata", "resultDigest", "delivery");
            if (Text(r, "executionId") != request.OperationId.ToString("N") || Text(r, "grantId") != request.ExpectedGrantId.ToString("N")) throw new JsonException();
            string outcome = Text(r, "outcome"), delivery = Text(r, "delivery"); bool replay = r.GetProperty("isReplay").GetBoolean();
            if (outcome is not ("ExecutedMcpSecurityInspection" or "AlreadyConsumed" or "CommittedRead" or "Unknown/recovery-required" or "Expired" or "Suspended" or "Revoked" or "UseLimitExhausted")) throw new JsonException();
            if (action == "status" && (outcome is not ("CommittedRead" or "Unknown/recovery-required") || !replay) || action == "execute" && outcome is ("CommittedRead" or "Unknown/recovery-required")) throw new JsonException();
            if (delivery is not ("response_prepared_client_receipt_unproven" or "client_receipt_unproven")) throw new JsonException();
            string? commitment = r.GetProperty("resultDigest").ValueKind == JsonValueKind.Null ? null : Text(r, "resultDigest");
            if (commitment is not null && !LowerHex(commitment)) throw new JsonException();
            if (outcome == "AlreadyConsumed" && !replay || outcome is not ("ExecutedMcpSecurityInspection" or "CommittedRead") && commitment is not null) throw new JsonException();
            McpSecurityInspection? inspection = null; var m = r.GetProperty("metadata");
            if (outcome == "ExecutedMcpSecurityInspection")
            {
                if (replay || commitment is null || action != "execute") throw new JsonException();
                Shape(m,"schema","resourceAlias","operation","decision","tool","contractVersion","contractDigest","toolVersion","integration","transportProfile","contractAuthority","remoteHostAttested","stdioStatus","callerCategory","requiredScope","delegation","currentServerAuthorizationRequired","executionPolicyStatus","inputSchemaDigest","requiredInputs","outputSchemaDeclared","inputConstraints","outputConstraints","maximumRequestBytes","maximumResponseBytes","cooperativeDeadlineMilliseconds","observedAt","inspectionOnly","executionAuthorityGranted");
                string decision=Text(m,"decision");string? tool=NullableText(m,"tool"),scope=NullableText(m,"requiredScope"),caller=NullableText(m,"callerCategory"),digest=NullableText(m,"contractDigest"),inputDigest=NullableText(m,"inputSchemaDigest");
                if(Text(m,"schema")!="aegir.skill.mcp-security-output/v1"||Text(m,"resourceAlias")!=request.ResourceAlias||Text(m,"operation")!="application.mcp.security.inspect"||
                    Text(m,"contractVersion")!="aegir.mcp.security-contract/v1"||Text(m,"integration")!="aegir.managed-http.v1"||Text(m,"transportProfile")!="aegir-custom-http-jsonrpc"||
                    Text(m,"contractAuthority")!="executing-auth-assembly"||m.GetProperty("remoteHostAttested").GetBoolean()||!m.GetProperty("inspectionOnly").GetBoolean()||m.GetProperty("executionAuthorityGranted").GetBoolean()||
                    decision is not("Observed"or"Indeterminate"or"Unavailable")||digest is not null&&!LowerHex(digest)||inputDigest is not null&&!LowerHex(inputDigest))throw new JsonException();
                var required=m.GetProperty("requiredInputs");if(required.ValueKind!=JsonValueKind.Array||required.GetArrayLength()>32)throw new JsonException();
                var fields=required.EnumerateArray().Select(v=>v.ValueKind==JsonValueKind.String?v.GetString()!:throw new JsonException()).ToArray();if(fields.Any(v=>!Identifier(v))||fields.Distinct(StringComparer.Ordinal).Count()!=fields.Length)throw new JsonException();
                if(decision=="Unavailable"&&(tool is not null||scope is not null||caller is not null||digest is not null||inputDigest is not null||fields.Length!=0)||decision!="Unavailable"&&tool!=request.Tool)throw new JsonException();
                if(scope is not null&&scope is not("developer:read"or"agent:read"or"transaction:write"or"transaction:read"or"agent:message"or"security:read"))throw new JsonException();
                if(caller is not null&&caller is not("current-agent"or"current-developer-account"or"current-developer-account-or-agent"))throw new JsonException();
                if(m.GetProperty("maximumRequestBytes").GetInt32() is not(0 or 65536)||m.GetProperty("maximumResponseBytes").GetInt32() is not(0 or 262144)||m.GetProperty("cooperativeDeadlineMilliseconds").GetInt32() is not(0 or 30000)||m.GetProperty("observedAt").GetInt64()<0)throw new JsonException();
                string stdio=Text(m,"stdioStatus");if(stdio is not("delegated-stdio-unsupported"or"not-inspected-no-parity-claim"))throw new JsonException();
                inspection=new(request.ResourceAlias,tool,decision,scope,caller,digest,inputDigest,fields,stdio,m.GetProperty("observedAt").GetInt64());
            }
            else if (m.ValueKind != JsonValueKind.Null || outcome == "CommittedRead" && commitment is null) throw new JsonException();
            return new(request.OperationId, outcome, request.ExpectedGrantId, replay, inspection, commitment, delivery);
        }
        catch (McpSecuritySkillApiException) { throw; }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        { throw new McpSecuritySkillApiException(request.OperationId, true); }
    }
    private static bool Identifier(string? s)=>s is{Length:>=1 and <=128}&&s.All(c=>char.IsAsciiLetterOrDigit(c)||c is '_'or'-'or'.'or':');
    private static bool ToolName(string? s)=>s is{Length:>0 and <=64}&&s.All(c=>c is >= 'a'and <= 'z'or >= '0'and <= '9'or '_');
    private static string? NullableText(JsonElement e,string n)=>e.GetProperty(n).ValueKind==JsonValueKind.Null?null:Text(e,n);
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
