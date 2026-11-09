// Copyright Foxlin Industries. Source-only bounded C7 client; no automatic retries, signing, execution authority or key discovery.
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record AegirSecureExecutionRequest(Guid OperationId,string SkillKey,string Version,string ManifestDigest,string AdapterDigest,
    string ResourceAlias,string TenantId,string AgentId,Guid RootGrantId,Guid ExpectedGrantId);
public sealed record AegirSecureExecutionResult(Guid OperationId,string Outcome,Guid GrantId,bool IsReplay,JsonElement? Metadata,
    AegirSecureExecutionArtifact? Receipt,AegirSecureReceiptVerification? ArtifactVerification,string ClientDelivery);
public sealed class AegirSecureExecutionApiException(Guid operationId,int? statusCode=null):Exception("Secure execution response refused or uncertain; preserve the original operation ID and explicitly reconcile. Values suppressed.")
{
    public Guid OperationId=>operationId;
    public int? StatusCode=>statusCode;
    public bool RequiresReconciliation=>true;
}

/// <summary>Plain metadata is authenticated by HTTPS. The public verifier cannot recompute the server-private
/// HMAC result commitment and does not independently authenticate plaintext metadata or observe SQL commitment.</summary>
public sealed class AegirSecureExecutionSkillApiClient:IDisposable
{
    private readonly HttpClient http;
    private readonly string key,reference;
    private readonly AegirReceiptTrustedServiceKey trusted;
    public AegirSecureExecutionSkillApiClient(Uri endpoint,string agentKey,string installedReference,AegirReceiptTrustedServiceKey trustedServiceKey,string? loopbackCertificateSha256=null)
    {
        if(!endpoint.IsAbsoluteUri||endpoint is not{Scheme:"https",UserInfo:"",Query:"",Fragment:"",AbsolutePath:"/"}||
            string.IsNullOrEmpty(agentKey)||agentKey.Length>2048||agentKey.Any(char.IsControl)||!agentKey.Contains(':')||
            installedReference is null||installedReference.Length!=69||!installedReference.StartsWith("ags2_",StringComparison.Ordinal)||installedReference.AsSpan(5).ContainsAnyExcept("0123456789abcdef")||
            trustedServiceKey is null||trustedServiceKey.PublicKey is null||trustedServiceKey.PublicKey.Length is <1 or >4096||trustedServiceKey.PrincipalId!="aegir:service")
            throw new ArgumentException("Explicit HTTPS Agent, installed grant and separately trusted public service key required; values suppressed.");
        var handler=new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,UseProxy=false};
        if(loopbackCertificateSha256 is not null)
        {
            if(!endpoint.IsLoopback||loopbackCertificateSha256.Length!=64||!loopbackCertificateSha256.All(char.IsAsciiHexDigit))throw new ArgumentException("Explicit loopback certificate pin required.");
            handler.ServerCertificateCustomValidationCallback=(_,certificate,_,errors)=>certificate is not null&&
                certificate.GetCertHashString(HashAlgorithmName.SHA256).Equals(loopbackCertificateSha256,StringComparison.OrdinalIgnoreCase)&&
                (errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0&&certificate.NotBefore.ToUniversalTime()<=DateTime.UtcNow&&certificate.NotAfter.ToUniversalTime()>=DateTime.UtcNow;
        }
        http=new(handler){BaseAddress=endpoint,Timeout=TimeSpan.FromSeconds(30)};key=agentKey;reference=installedReference;
        trusted=trustedServiceKey with{PublicKey=(byte[])trustedServiceKey.PublicKey.Clone()};
    }
    public override string ToString()=>"AegirSecureExecutionSkillApiClient { credentials = [redacted], profile = pinned service-key artifact verification only }";
    public void Dispose()=>http.Dispose();
    public Task<AegirSecureExecutionResult> ExecuteAsync(AegirSecureExecutionRequest request,CancellationToken ct=default)=>SendAsync(request,"execute",ct);
    public Task<AegirSecureExecutionResult> ReconcileAsync(AegirSecureExecutionRequest original,CancellationToken ct=default)=>SendAsync(original,"status",ct);
    private async Task<AegirSecureExecutionResult> SendAsync(AegirSecureExecutionRequest r,string action,CancellationToken ct)
    {
        if(r is null||r.OperationId==Guid.Empty||r.RootGrantId==Guid.Empty||r.ExpectedGrantId==Guid.Empty||!Hex(r.SkillKey)||!Hex(r.ManifestDigest)||!Hex(r.AdapterDigest)||
            string.IsNullOrEmpty(r.Version)||r.Version.Length>64||r.Version.Any(char.IsControl)||!Identifier(r.TenantId)||!Identifier(r.AgentId)||
            string.IsNullOrEmpty(r.ResourceAlias)||r.ResourceAlias.Length>160||r.ResourceAlias.Any(ch=>!char.IsAscii(ch)||char.IsControl(ch)))
            throw new ArgumentException("Invalid bounded C7 request and expected receipt context; values suppressed.");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));var stop=deadline.Token;
        using var message=new HttpRequestMessage(HttpMethod.Post,"/v1/skills/v2/secure-execution"){Content=JsonContent.Create(new
        {action,operationId=r.OperationId.ToString("N"),skillKey=r.SkillKey,skillVersion=r.Version,manifestDigest=r.ManifestDigest,adapterDigest=r.AdapterDigest,
            resourcePolicy="group.administration.metadata.read",resourceAlias=r.ResourceAlias,scope="security:read",operation="group.administration.metadata.execute-with-receipt"})};
        message.Headers.Add("X-Aegir-Agent-Key",key);message.Headers.Add("X-Aegir-Delegation",reference);message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response=await http.SendAsync(message,HttpCompletionOption.ResponseHeadersRead,stop);
            if(!response.IsSuccessStatusCode)throw new AegirSecureExecutionApiException(r.OperationId,(int)response.StatusCode);
            if(response.Content.Headers.ContentType?.MediaType!="application/json"||response.Content.Headers.ContentEncoding.Count!=0)throw new JsonException();
            using var stream=await response.Content.ReadAsStreamAsync(stop);using var bytes=new MemoryStream();byte[] buffer=new byte[2048];int n;
            while((n=await stream.ReadAsync(buffer,stop))>0){if(bytes.Length+n>16384)throw new JsonException();bytes.Write(buffer,0,n);}
            using var doc=JsonDocument.Parse(bytes.ToArray(),new JsonDocumentOptions{MaxDepth=5});var root=doc.RootElement;Shape(root,"schema","result");
            if(Text(root,"schema")!="aegir.secure-execution-skill.execution/v1")throw new JsonException();var result=root.GetProperty("result");
            Shape(result,"outcome","executionId","grantId","isReplay","metadata","receipt","verification","grantsAuthority","clientDelivery");
            if(Text(result,"executionId")!=r.OperationId.ToString("N")||Text(result,"grantId")!=r.ExpectedGrantId.ToString("N")||result.GetProperty("grantsAuthority").GetBoolean()||Text(result,"clientDelivery")!="unproven")throw new JsonException();
            string outcome=Text(result,"outcome");bool replay=result.GetProperty("isReplay").GetBoolean();
            if(outcome is not("ExecutedCommittedRead"or"HistoricalCommittedReceipt"or"Unknown/recovery-required"or"Revoked"or"Suspended"or"Expired"or"UseLimitExhausted")||
                action=="status"&&outcome is not("HistoricalCommittedReceipt"or"Unknown/recovery-required"))throw new JsonException();
            if(Text(result,"verification")!=(outcome=="HistoricalCommittedReceipt"?"Valid":"not-performed"))throw new JsonException();
            AegirSecureExecutionArtifact? artifact=null;AegirSecureReceiptVerification? verification=null;JsonElement? metadata=null;
            if(outcome is "ExecutedCommittedRead"or"HistoricalCommittedReceipt")
            {
                artifact=AegirSecureExecutionReceiptVerifier.Parse(result.GetProperty("receipt"));
                if(artifact.Claims["skillKey"]!=r.SkillKey||artifact.Claims["skillVersion"]!=r.Version||artifact.Claims["manifestDigest"]!=r.ManifestDigest||artifact.Claims["adapterDigest"]!=r.AdapterDigest)throw new JsonException();
                verification=AegirSecureExecutionReceiptVerifier.Verify(artifact,trusted,new(r.OperationId,r.TenantId,r.AgentId,r.RootGrantId,r.ExpectedGrantId,r.ResourceAlias));
                if(!verification.IsArtifactValidForPinnedContext)throw new JsonException();
            }
            else if(result.GetProperty("receipt").ValueKind!=JsonValueKind.Null)throw new JsonException();
            if(outcome=="ExecutedCommittedRead")
            {
                if(action!="execute"||replay)throw new JsonException();var m=result.GetProperty("metadata");Shape(m,"resourceAlias","depth","status");
                if(Text(m,"resourceAlias")!=r.ResourceAlias||Text(m,"status")!="Active"||m.GetProperty("depth").GetInt32()is <1 or >128)throw new JsonException();metadata=m.Clone();
            }
            else if(result.GetProperty("metadata").ValueKind!=JsonValueKind.Null||outcome is "HistoricalCommittedReceipt"or"Unknown/recovery-required"&&!replay)throw new JsonException();
            return new(r.OperationId,outcome,r.ExpectedGrantId,replay,metadata,artifact,verification,"unproven");
        }
        catch(AegirSecureExecutionApiException){throw;}
        catch(Exception e)when(e is HttpRequestException or OperationCanceledException or IOException or JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        {throw new AegirSecureExecutionApiException(r.OperationId);}
    }
    private static bool Hex(string s)=>s is{Length:64}&&s.All(c=>c is >= '0'and <= '9'or >= 'a'and <= 'f');
    private static bool Identifier(string s)=>s is{Length:>=1 and <=128}&&s.All(c=>char.IsAsciiLetterOrDigit(c)||c is '_'or'-'or'.'or':');
    private static string Text(JsonElement r,string n)=>r.GetProperty(n).ValueKind==JsonValueKind.String?r.GetProperty(n).GetString()!:throw new JsonException();
    private static void Shape(JsonElement r,params string[] names)
    {if(r.ValueKind!=JsonValueKind.Object)throw new JsonException();var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var p in r.EnumerateObject())if(!names.Contains(p.Name,StringComparer.Ordinal)||!seen.Add(p.Name))throw new JsonException();if(seen.Count!=names.Length)throw new JsonException();}
}
