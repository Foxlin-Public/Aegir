// Copyright Foxlin Industries. Unreleased source-only delegated HTTP MCP integration.
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text.Json;

namespace Foxlin.Aegir.Auth.Delegation;

public sealed record DelegatedMetadataRequest(Guid OperationId,string ResourcePolicy,string ResourceAlias);
public sealed record DelegatedMetadata(string ResourceAlias,string Status,bool? EmailVerified,int? Depth);
public sealed record DelegatedMetadataResult(Guid OperationId,string Outcome,string? GrantId,bool IsReplay,DelegatedMetadata? Metadata);
/// <summary>Keep the same durable operation identity for reconciliation; never assume an uncertain request was refused.</summary>
public sealed class DelegatedMcpException(Guid operationId,bool requiresReconciliation,int? statusCode=null)
    :Exception(requiresReconciliation?"Delegated MCP outcome is uncertain; reconcile the same operation identity.":"Delegated MCP request was refused.")
{
    public Guid OperationId=>operationId;
    public bool RequiresReconciliation=>requiresReconciliation;
    public int? StatusCode=>statusCode;
}
/// <summary>Explicit current Agent key plus its own opaque reference. HTTP MCP only; no ambient fallback or Human token.</summary>
public sealed class AegirDelegatedMcpClient:IDisposable
{
    private readonly HttpClient http;private readonly string agentKey,reference;
    private static readonly string[] ForbiddenHeaders=["Authorization","X-Aegir-Developer-Key","X-Aegir-Session-Token","X-Aegir-Agent-Key","X-Aegir-Delegation","Idempotency-Key"];
    public AegirDelegatedMcpClient(Uri endpoint,string agentKey,string delegationReference,string? loopbackCertificateSha256=null)
    {
        if(!endpoint.IsAbsoluteUri||endpoint is not{Scheme:"https",UserInfo:"",Query:"",Fragment:"",AbsolutePath:"/"}||
            string.IsNullOrEmpty(agentKey)||agentKey.Length>2048||agentKey.Any(char.IsControl)||!agentKey.Contains(':')||
            delegationReference.Length!=69||!delegationReference.StartsWith("agd3_",StringComparison.Ordinal)&&!delegationReference.StartsWith("agd4_",StringComparison.Ordinal)||
            delegationReference.AsSpan(5).ContainsAnyExcept("0123456789abcdef"))throw new ArgumentException("Explicit HTTPS Agent/delegation transport is required; credential values suppressed.");
        var handler=new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,UseProxy=false};
        if(loopbackCertificateSha256 is not null)
        {
            if(!endpoint.IsLoopback||loopbackCertificateSha256.Length!=64||loopbackCertificateSha256.Any(c=>!char.IsAsciiHexDigit(c)))throw new ArgumentException("A valid explicit loopback certificate pin is required.");
            handler.ServerCertificateCustomValidationCallback=(_,certificate,_,errors)=>certificate is not null&&
                string.Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256),loopbackCertificateSha256,StringComparison.OrdinalIgnoreCase)&&
                (errors&SslPolicyErrors.RemoteCertificateNameMismatch)==0&&certificate.NotBefore.ToUniversalTime()<=DateTime.UtcNow&&certificate.NotAfter.ToUniversalTime()>=DateTime.UtcNow;
        }
        http=new HttpClient(handler){BaseAddress=endpoint,Timeout=TimeSpan.FromSeconds(30)};this.agentKey=agentKey;reference=delegationReference;
    }
    public void Dispose()=>http.Dispose();
    public override string ToString()=>"AegirDelegatedMcpClient { credentials = [redacted], transport = HTTP MCP }";
    public async Task<DelegatedMetadataResult> ReadMetadataAsync(DelegatedMetadataRequest request,CancellationToken cancellationToken=default)
    {
        if(request.OperationId==Guid.Empty||request.ResourcePolicy is not("self.account.metadata.read"or"group.administration.metadata.read")||
            request.ResourceAlias.Length is <1 or >160||request.ResourceAlias.Any(char.IsControl))throw new ArgumentException("Invalid bounded delegated metadata request.");
        if(ForbiddenHeaders.Any(http.DefaultRequestHeaders.Contains))throw new DelegatedMcpException(request.OperationId,false);
        string rpc=Guid.NewGuid().ToString("N");using var message=new HttpRequestMessage(HttpMethod.Post,"/mcp"){
            Content=JsonContent.Create(new{jsonrpc="2.0",id=rpc,method="tools/call",@params=new{name="delegated_metadata_read_v1",arguments=new{
                operationId=request.OperationId.ToString("N"),resourcePolicy=request.ResourcePolicy,resourceAlias=request.ResourceAlias,scope="security:read"}}})};
        message.Headers.Add("X-Aegir-Agent-Key",agentKey);message.Headers.Add("X-Aegir-Delegation",reference);
        message.Headers.Accept.ParseAdd("application/json");
        try
        {
            using var response=await http.SendAsync(message,HttpCompletionOption.ResponseHeadersRead,cancellationToken);
            if(!response.IsSuccessStatusCode)throw new DelegatedMcpException(request.OperationId,(int)response.StatusCode>=500||(int)response.StatusCode is >=300 and <400||response.StatusCode is (HttpStatusCode)408 or (HttpStatusCode)499,(int)response.StatusCode);
            using var stream=await response.Content.ReadAsStreamAsync(cancellationToken);using var bounded=new MemoryStream();byte[] bytes=new byte[2048];int n;
            while((n=await stream.ReadAsync(bytes,cancellationToken))>0){if(bounded.Length+n>16384)throw new DelegatedMcpException(request.OperationId,true);bounded.Write(bytes,0,n);}
            using var doc=JsonDocument.Parse(bounded.ToArray(),new JsonDocumentOptions{MaxDepth=8});var root=doc.RootElement;Shape(root,"jsonrpc","id","result");
            if(root.GetProperty("jsonrpc").GetString()!="2.0"||root.GetProperty("id").GetString()!=rpc)throw new JsonException();
            var value=root.GetProperty("result");Shape(value,"schema","operationId","outcome","grantId","isReplay","metadata");
            if(value.GetProperty("schema").GetString()!="aegir.delegated-mcp.metadata/v1"||value.GetProperty("operationId").GetString()!=request.OperationId.ToString("N"))throw new JsonException();
            string outcome=value.GetProperty("outcome").GetString()!;bool replay=value.GetProperty("isReplay").GetBoolean();var meta=value.GetProperty("metadata");DelegatedMetadata? data=null;
            if(outcome=="AuthorizedMetadata")
            {
                if(replay)throw new JsonException();
                if(request.ResourcePolicy=="self.account.metadata.read"){Shape(meta,"resourceAlias","status","emailVerified");data=new(request.ResourceAlias,Text(meta,"status",32),meta.GetProperty("emailVerified").GetBoolean(),null);}
                else{Shape(meta,"resourceAlias","depth","status");int depth=meta.GetProperty("depth").GetInt32();if(depth is <1 or >128)throw new JsonException();data=new(request.ResourceAlias,Text(meta,"status",32),null,depth);}
                if(Text(meta,"resourceAlias",160)!=request.ResourceAlias)throw new JsonException();
            }
            else if(outcome is "AlreadyConsumed"or"Revoked"or"Suspended"or"Expired"or"UseLimitExhausted")
            {if(meta.ValueKind!=JsonValueKind.Null||outcome=="AlreadyConsumed"&&!replay)throw new JsonException();}
            else throw new JsonException();
            string? grant=value.GetProperty("grantId").ValueKind==JsonValueKind.Null?null:Text(value,"grantId",32);
            if(grant is null||grant.Length!=32||!Guid.TryParseExact(grant,"N",out _))throw new JsonException();
            return new(request.OperationId,outcome,grant,replay,data);
        }
        catch(DelegatedMcpException){throw;}
        catch(Exception e)when(e is HttpRequestException or IOException or OperationCanceledException or JsonException or InvalidOperationException or FormatException)
        {throw new DelegatedMcpException(request.OperationId,true);}
    }
    private static string Text(JsonElement root,string name,int bound)
    {string value=root.GetProperty(name).GetString()??throw new JsonException();if(value.Length>bound||value.Any(char.IsControl))throw new JsonException();return value;}
    private static void Shape(JsonElement root,params string[] fields)
    {if(root.ValueKind!=JsonValueKind.Object)throw new JsonException();var names=root.EnumerateObject().Select(p=>p.Name).ToArray();if(names.Length!=fields.Length||names.Distinct(StringComparer.Ordinal).Count()!=names.Length||names.Except(fields,StringComparer.Ordinal).Any())throw new JsonException();}
}
