// Copyright Foxlin Industries. Unreleased C1 source-only custom HTTP MCP consumer; no arbitrary Skill runner.
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record SkillMetadataRequest(Guid OperationId,string SkillKey,string Version,string ManifestDigest,string AdapterDigest,string ResourcePolicy,string ResourceAlias);
public sealed record SkillMetadataResult(Guid OperationId,string Outcome,string GrantId,bool IsReplay,DelegatedMetadata? Metadata,string? ResultCommitment,string Delivery)
{
    public bool RequiresReconciliation=>Outcome=="Unknown/recovery-required";
}
/// <summary>Exact newly consented Skill reference and current Agent key. Preserve the original request for explicit reconciliation; no automatic retry or fallback.</summary>
public sealed class AegirSkillMcpClient:IDisposable
{
    private readonly HttpClient http;private readonly string key,reference;
    public AegirSkillMcpClient(Uri endpoint,string agentKey,string skillReference,string? loopbackCertificateSha256=null):this(endpoint,agentKey,skillReference,loopbackCertificateSha256,false){}
    public static AegirSkillMcpClient ForInstalledSkill(Uri endpoint,string agentKey,string installedSkillReference,string? loopbackCertificateSha256=null)=>new(endpoint,agentKey,installedSkillReference,loopbackCertificateSha256,true);
    private AegirSkillMcpClient(Uri endpoint,string agentKey,string skillReference,string? loopbackCertificateSha256,bool installed)
    {
        if(!endpoint.IsAbsoluteUri||endpoint is not{Scheme:"https",UserInfo:"",Query:"",Fragment:"",AbsolutePath:"/"}||string.IsNullOrEmpty(agentKey)||agentKey.Length>2048||agentKey.Any(char.IsControl)||!agentKey.Contains(':')||
            skillReference.Length!=69||!skillReference.StartsWith(installed?"ags2_":"ags1_",StringComparison.Ordinal)||skillReference.AsSpan(5).ContainsAnyExcept("0123456789abcdef"))throw new ArgumentException("Explicit HTTPS current Agent and newly consented Skill reference required; values suppressed.");
        var handler=new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,UseProxy=false};
        if(loopbackCertificateSha256 is not null)
        {
            if(!endpoint.IsLoopback||!Hex(loopbackCertificateSha256))throw new ArgumentException("Explicit loopback certificate pin required.");
            handler.ServerCertificateCustomValidationCallback=(_,certificate,_,errors)=>certificate is not null&&string.Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256),loopbackCertificateSha256,StringComparison.OrdinalIgnoreCase)&&
                (errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0&&certificate.NotBefore.ToUniversalTime()<=DateTime.UtcNow&&certificate.NotAfter.ToUniversalTime()>=DateTime.UtcNow;
        }
        http=new HttpClient(handler){BaseAddress=endpoint,Timeout=TimeSpan.FromSeconds(30)};key=agentKey;reference=skillReference;
    }
    public void Dispose()=>http.Dispose();
    public override string ToString()=>"AegirSkillMcpClient { credentials = [redacted], profile = C1 metadata-only HTTP MCP }";
    public Task<SkillMetadataResult> ExecuteAsync(SkillMetadataRequest request,CancellationToken cancellationToken=default)=>SendAsync(request,"execute",cancellationToken);
    public Task<SkillMetadataResult> ReconcileAsync(SkillMetadataRequest originalRequest,CancellationToken cancellationToken=default)=>SendAsync(originalRequest,"status",cancellationToken);
    private async Task<SkillMetadataResult> SendAsync(SkillMetadataRequest request,string action,CancellationToken ct)
    {
        if(request.OperationId==Guid.Empty||!LowerHex(request.SkillKey)||!LowerHex(request.ManifestDigest)||!LowerHex(request.AdapterDigest)||request.Version.Length is <1 or >64||request.Version.Any(char.IsControl)||
            request.ResourcePolicy is not("self.account.metadata.read"or"group.administration.metadata.read")||request.ResourceAlias.Length is <1 or >160||request.ResourceAlias.Any(char.IsControl))throw new ArgumentException("Invalid bounded Skill request; values suppressed.");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));var stop=deadline.Token;
        string id=Guid.NewGuid().ToString("N");using var message=new HttpRequestMessage(HttpMethod.Post,"/mcp"){Content=JsonContent.Create(new{jsonrpc="2.0",id,method="tools/call",@params=new{name="skill_metadata_execute_v1",arguments=new{
            action,operationId=request.OperationId.ToString("N"),skillKey=request.SkillKey,skillVersion=request.Version,manifestDigest=request.ManifestDigest,adapterDigest=request.AdapterDigest,resourcePolicy=request.ResourcePolicy,resourceAlias=request.ResourceAlias,scope="security:read"}}})};
        message.Headers.Add("X-Aegir-Agent-Key",key);message.Headers.Add("X-Aegir-Delegation",reference);message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response=await http.SendAsync(message,HttpCompletionOption.ResponseHeadersRead,stop);
            if(!response.IsSuccessStatusCode)throw new DelegatedMcpException(request.OperationId,(int)response.StatusCode>=500||(int)response.StatusCode is >=300 and <400||response.StatusCode is HttpStatusCode.RequestTimeout or (HttpStatusCode)499,(int)response.StatusCode);
            using var stream=await response.Content.ReadAsStreamAsync(stop);using var bytes=new MemoryStream();byte[] chunk=new byte[2048];int n;
            while((n=await stream.ReadAsync(chunk,stop))>0){if(bytes.Length+n>16384)throw new DelegatedMcpException(request.OperationId,true);bytes.Write(chunk,0,n);}
            using var doc=JsonDocument.Parse(bytes.ToArray(),new JsonDocumentOptions{MaxDepth=8});var root=doc.RootElement;Shape(root,"jsonrpc","id","result");
            if(root.GetProperty("jsonrpc").GetString()!="2.0"||root.GetProperty("id").GetString()!=id)throw new JsonException();
            var result=root.GetProperty("result");Shape(result,"schema","outcome","executionId","grantId","isReplay","metadata","resultDigest","delivery");
            if(result.GetProperty("schema").GetString()!="aegir.skill.execution/v1"||result.GetProperty("executionId").GetString()!=request.OperationId.ToString("N"))throw new JsonException();
            string outcome=Text(result,"outcome",64),grant=Text(result,"grantId",32),delivery=Text(result,"delivery",64);if(!Guid.TryParseExact(grant,"N",out _)||delivery is not("response_prepared_client_receipt_unproven"or"client_receipt_unproven"))throw new JsonException();
            bool replay=result.GetProperty("isReplay").GetBoolean();string? commitment=result.GetProperty("resultDigest").ValueKind==JsonValueKind.Null?null:Text(result,"resultDigest",64);if(commitment is not null&&!Hex(commitment))throw new JsonException();
            var metadata=result.GetProperty("metadata");DelegatedMetadata? data=null;
            if(outcome=="ExecutedMetadata")
            {
                if(action!="execute"||replay||commitment is null)throw new JsonException();
                if(request.ResourcePolicy=="self.account.metadata.read"){Shape(metadata,"resourceAlias","status","emailVerified");data=new(request.ResourceAlias,Text(metadata,"status",32),metadata.GetProperty("emailVerified").GetBoolean(),null);}
                else{Shape(metadata,"resourceAlias","status","depth");int depth=metadata.GetProperty("depth").GetInt32();if(depth is <1 or >128)throw new JsonException();data=new(request.ResourceAlias,Text(metadata,"status",32),null,depth);}
                if(Text(metadata,"resourceAlias",160)!=request.ResourceAlias)throw new JsonException();
            }
            else
            {
                if(metadata.ValueKind!=JsonValueKind.Null)throw new JsonException();
                if(outcome=="CommittedRead"){if(action!="status"||!replay||commitment is null)throw new JsonException();}
                else if(outcome=="Unknown/recovery-required"){if(action!="status"||!replay||commitment is not null)throw new JsonException();}
                else if(outcome=="AlreadyConsumed"){if(action!="execute"||!replay)throw new JsonException();}
                else if(outcome is "Revoked"or"Suspended"or"Expired"or"UseLimitExhausted"){if(action!="execute")throw new JsonException();}
                else throw new JsonException();
            }
            return new(request.OperationId,outcome,grant,replay,data,commitment,delivery);
        }
        catch(DelegatedMcpException){throw;}
        catch(Exception e)when(e is HttpRequestException or IOException or OperationCanceledException or JsonException or InvalidOperationException or FormatException)
        {throw new DelegatedMcpException(request.OperationId,true);}
    }
    private static bool LowerHex(string value)=>Hex(value)&&value==value.ToLowerInvariant();
    private static bool Hex(string value)=>value.Length==64&&value.All(char.IsAsciiHexDigit);
    private static string Text(JsonElement root,string name,int max){string value=root.GetProperty(name).GetString()??throw new JsonException();if(value.Length is <1||value.Length>max||value.Any(char.IsControl))throw new JsonException();return value;}
    private static void Shape(JsonElement root,params string[] fields)
    {if(root.ValueKind!=JsonValueKind.Object)throw new JsonException();var keys=root.EnumerateObject().Select(x=>x.Name).ToArray();if(keys.Length!=fields.Length||keys.Distinct(StringComparer.Ordinal).Count()!=keys.Length||keys.Except(fields,StringComparer.Ordinal).Any())throw new JsonException();}
}
