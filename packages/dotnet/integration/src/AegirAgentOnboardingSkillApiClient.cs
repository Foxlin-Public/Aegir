// Copyright Foxlin Industries. Unreleased source-only C6 enrollment preparation; never identity or credential creation.
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record AgentEnrollmentCandidate(string Name,string IdentityClass,string IdentityReference,string CredentialCustody,string[] Capabilities);
public sealed record AgentOnboardingPreparationRequest(Guid OperationId,string SkillKey,string Version,string ManifestDigest,string AdapterDigest,string ResourceAlias,Guid ExpectedGrantId,AgentEnrollmentCandidate Enrollment);
public sealed record AgentEnrollmentPreparation(string ResourceAlias,string Decision,string IdentityClass,string IdentityUniqueness,string[] ValidatedCapabilities,string[] MissingPrerequisites,string[] UninspectedRegistrationFields,long ObservedAt);
public sealed record AgentOnboardingPreparationResult(Guid OperationId,string Outcome,Guid GrantId,bool IsReplay,AgentEnrollmentPreparation? Preparation,string? ResultCommitment,string Delivery);
public sealed class AgentOnboardingSkillApiException(Guid operationId, bool requiresReconciliation, int? statusCode = null)
    : Exception(requiresReconciliation ? "Agent onboarding preparation outcome uncertain; explicitly reconcile the original operation." : "Agent onboarding preparation refused; values suppressed.")
{
    public Guid OperationId => operationId;
    public bool RequiresReconciliation => requiresReconciliation;
    public int? StatusCode => statusCode;
}

/// <summary>Exact installed reference/current Agent key and consented enrollment candidate.
/// An preparation result is an observation, never issuance authority. No automatic retry.</summary>
public sealed class AegirAgentOnboardingSkillApiClient : IDisposable
{
    private readonly HttpClient http;
    private readonly string key, reference;
    public AegirAgentOnboardingSkillApiClient(Uri endpoint, string agentKey, string installedReference, string? loopbackCertificateSha256 = null)
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
    public override string ToString() => "AegirAgentOnboardingSkillApiClient { credentials = [redacted], operation = Agent enrollment preparation only }";
    public Task<AgentOnboardingPreparationResult> PrepareAsync(AgentOnboardingPreparationRequest request, CancellationToken cancellationToken = default) => SendAsync(request, "execute", cancellationToken);
    public Task<AgentOnboardingPreparationResult> ReconcileAsync(AgentOnboardingPreparationRequest originalRequest, CancellationToken cancellationToken = default) => SendAsync(originalRequest, "status", cancellationToken);
    private async Task<AgentOnboardingPreparationResult> SendAsync(AgentOnboardingPreparationRequest request, string action, CancellationToken ct)
    {
        if (request is null || request.OperationId == Guid.Empty || request.ExpectedGrantId == Guid.Empty || !LowerHex(request.SkillKey) || !LowerHex(request.ManifestDigest) || !LowerHex(request.AdapterDigest) ||
            string.IsNullOrEmpty(request.Version) || request.Version.Length > 64 || request.Version.Any(char.IsControl) || string.IsNullOrEmpty(request.ResourceAlias) || request.ResourceAlias.Length > 160 || request.ResourceAlias.Any(char.IsControl) || !Candidate(request.Enrollment))
            throw new ArgumentException("Invalid bounded Agent onboarding preparation request; values suppressed.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30)); var stop = deadline.Token;
        using var message = new HttpRequestMessage(HttpMethod.Post, "/v1/skills/v2/agent-onboarding-preparation") { Content = JsonContent.Create(new
        { action, operationId = request.OperationId.ToString("N"), skillKey = request.SkillKey, skillVersion = request.Version, manifestDigest = request.ManifestDigest, adapterDigest = request.AdapterDigest,
            resourcePolicy = "application.agent-onboarding.preparation.read", resourceAlias = request.ResourceAlias, scope = "security:read", operation = "application.agent-onboarding.prepare",enrollment=request.Enrollment }) };
        message.Headers.Add("X-Aegir-Agent-Key", key); message.Headers.Add("X-Aegir-Delegation", reference); message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, stop);
            if (!response.IsSuccessStatusCode) throw new AgentOnboardingSkillApiException(request.OperationId, (int)response.StatusCode >= 500 || (int)response.StatusCode is >= 300 and < 400 or 408 or 499, (int)response.StatusCode);
            if (response.Content.Headers.ContentType?.MediaType != "application/json") throw new JsonException();
            using var stream = await response.Content.ReadAsStreamAsync(stop); using var bytes = new MemoryStream(); byte[] buffer = new byte[2048]; int n;
            while ((n = await stream.ReadAsync(buffer, stop)) > 0) { if (bytes.Length + n > 16384) throw new JsonException(); bytes.Write(buffer, 0, n); }
            using var doc = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 5 }); var root = doc.RootElement; Shape(root, "schema", "result");
            if (Text(root, "schema") != "aegir.agent-onboarding-skill.execution/v1") throw new JsonException();
            var r = root.GetProperty("result"); Shape(r, "outcome", "executionId", "grantId", "isReplay", "metadata", "resultDigest", "delivery");
            if (Text(r, "executionId") != request.OperationId.ToString("N") || Text(r, "grantId") != request.ExpectedGrantId.ToString("N")) throw new JsonException();
            string outcome = Text(r, "outcome"), delivery = Text(r, "delivery"); bool replay = r.GetProperty("isReplay").GetBoolean();
            if (outcome is not ("PreparedAgentEnrollment" or "AlreadyConsumed" or "CommittedRead" or "Unknown/recovery-required" or "Expired" or "Suspended" or "Revoked" or "UseLimitExhausted")) throw new JsonException();
            if (action == "status" && (outcome is not ("CommittedRead" or "Unknown/recovery-required") || !replay) || action == "execute" && outcome is ("CommittedRead" or "Unknown/recovery-required")) throw new JsonException();
            if (delivery is not ("response_prepared_client_receipt_unproven" or "client_receipt_unproven")) throw new JsonException();
            string? commitment = r.GetProperty("resultDigest").ValueKind == JsonValueKind.Null ? null : Text(r, "resultDigest");
            if (commitment is not null && !LowerHex(commitment)) throw new JsonException();
            if (outcome == "AlreadyConsumed" && !replay || outcome is not ("PreparedAgentEnrollment" or "CommittedRead") && commitment is not null) throw new JsonException();
            AgentEnrollmentPreparation? preparation=null;var m=r.GetProperty("metadata");
            if(outcome=="PreparedAgentEnrollment")
            {
                if(replay||commitment is null||action!="execute")throw new JsonException();
                Shape(m,"schema","resourceAlias","operation","decision","identityClass","identityUniqueness","canonicalRegistrationPolicy","requiredProvisionerScope","validatedCapabilities","provisionerAuthorityVerified","credentialCustodyVerified","registrationCapacity","missingPrerequisites","uninspectedRegistrationFields","groupAssigned","proposalCreated","identityCreated","credentialIssued","approvalGranted","issuanceAuthorized","delegationAuthorityGranted","privateKeyExportPermitted","preparationOnly","nextAuthorizedAction","observedAt");
                string decision=Text(m,"decision"),identityClass=Text(m,"identityClass"),uniqueness=Text(m,"identityUniqueness");
                if(Text(m,"schema")!="aegir.skill.agent-onboarding-output/v1"||Text(m,"resourceAlias")!=request.ResourceAlias||Text(m,"operation")!="application.agent-onboarding.prepare"||
                    !m.GetProperty("preparationOnly").GetBoolean()||new[]{"provisionerAuthorityVerified","credentialCustodyVerified","groupAssigned","proposalCreated","identityCreated","credentialIssued","approvalGranted","issuanceAuthorized","delegationAuthorityGranted","privateKeyExportPermitted"}.Any(n=>m.GetProperty(n).GetBoolean())||
                    decision is not("ConfigurationValidated"or"UnsupportedIdentityClass"or"UnsupportedCredentialCustody"or"BlockedCapabilities"or"ExistingIdentityNotReusable"or"IdentityReferenceUnavailable")||
                    identityClass is not("registered-agent"or"unsupported")||uniqueness is not("server-assigned-at-issuance-not-reserved"or"existing-identity-not-reusable"or"identity-reference-unavailable")||
                    Text(m,"canonicalRegistrationPolicy")!="current-developer-management-agent-write-owned-application"||Text(m,"requiredProvisionerScope")!="agent:write"||
                    Text(m,"registrationCapacity")!="not-defined-by-current-registration-contract-recheck-at-issuance"||
                    Text(m,"nextAuthorizedAction")!=(decision=="ConfigurationValidated"?"separate-authorized-developer-registration-with-approved-custody":"correct-blocked-or-unsupported-prerequisites")||m.GetProperty("observedAt").GetInt64()<0)throw new JsonException();
                var capabilities=Strings(m,"validatedCapabilities",16);var missing=Strings(m,"missingPrerequisites",4);var uninspected=Strings(m,"uninspectedRegistrationFields",3);
                if(!missing.SequenceEqual(new[]{"independent-current-provisioner-authorization","approved-credential-custody","issuance-time-identity-and-capacity-check","separate-group-assignment-if-required"})||
                    !uninspected.SequenceEqual(new[]{"provider","model","lifetime"})||
                    decision=="ConfigurationValidated"&&!capabilities.SequenceEqual(request.Enrollment.Capabilities.OrderBy(v=>v,StringComparer.Ordinal))||decision!="ConfigurationValidated"&&capabilities.Length!=0)throw new JsonException();
                preparation=new(request.ResourceAlias,decision,identityClass,uniqueness,capabilities,missing,uninspected,m.GetProperty("observedAt").GetInt64());
            }
            else if(m.ValueKind!=JsonValueKind.Null||outcome=="CommittedRead"&&commitment is null)throw new JsonException();
            return new(request.OperationId,outcome,request.ExpectedGrantId,replay,preparation,commitment,delivery);
        }
        catch (AgentOnboardingSkillApiException) { throw; }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        { throw new AgentOnboardingSkillApiException(request.OperationId, true); }
    }
    private static bool Identifier(string? s)=>s is{Length:>=1 and <=128}&&s.All(c=>char.IsAsciiLetterOrDigit(c)||c is '_'or'-'or'.'or':');
    private static bool Candidate(AgentEnrollmentCandidate? c)=>c is not null&&!string.IsNullOrWhiteSpace(c.Name)&&c.Name.Length<=1024&&!c.Name.Any(char.IsControl)&&Identifier(c.IdentityClass)&&Identifier(c.IdentityReference)&&Identifier(c.CredentialCustody)&&c.Capabilities is{Length:>=1 and <=16}&&c.Capabilities.All(Identifier)&&c.Capabilities.Distinct(StringComparer.Ordinal).Count()==c.Capabilities.Length;
    private static string[] Strings(JsonElement m,string name,int maximum)
    {var array=m.GetProperty(name);if(array.ValueKind!=JsonValueKind.Array||array.GetArrayLength()>maximum)throw new JsonException();var values=array.EnumerateArray().Select(v=>v.ValueKind==JsonValueKind.String?v.GetString()!:throw new JsonException()).ToArray();if(values.Any(v=>!Identifier(v))||values.Distinct(StringComparer.Ordinal).Count()!=values.Length)throw new JsonException();return values;}
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
