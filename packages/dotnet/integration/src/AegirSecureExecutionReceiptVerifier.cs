// Copyright Foxlin Industries. Source-only pinned public-key artifact verification; no authorization, SQL or network calls.
#pragma warning disable SYSLIB5006 // .NET10 platform ML-DSA-65; no fallback or keyless signature claim.
using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace Foxlin.Aegir.Auth.Delegation;

public sealed record AegirSecureExecutionArtifact(
    [property:JsonPropertyName("claims")]IReadOnlyDictionary<string,string> Claims,
    [property:JsonPropertyName("signature")]string Signature);
public sealed record AegirReceiptTrustedServiceKey(string KeyId,string PrincipalId,byte[] PublicKey,DateTimeOffset ActivatedAtUtc,DateTimeOffset? RetiredAtUtc=null,DateTimeOffset? RevokedAtUtc=null);
public sealed record AegirReceiptExpectedContext(Guid OperationId,string TenantId,string AgentId,Guid RootGrantId,Guid GrantId,string ResourceAlias);
public sealed record AegirSecureReceiptVerification(string Classification,bool CryptographicallyValid,bool ExpectedContextValid,
    bool CurrentAuthorityEstablished=false,bool ClientDeliveryProven=false,bool ExternalEffectsProven=false,bool DurableStateIndependentlyObserved=false)
{
    public bool IsArtifactValidForPinnedContext=>CryptographicallyValid&&ExpectedContextValid;
}

/// <summary>Trust inputs must come from an independently trusted application/operator channel, never the artifact itself.
/// A valid artifact proves a trusted service signed these claims. It cannot re-observe SQL/witness durability,
/// establish current permission, certify an external effect, or prove delivery. Production key distribution is separate.</summary>
public static class AegirSecureExecutionReceiptVerifier
{
    public const string Schema="aegir.skill.secure-execution-receipt/v1";
    private const string Domain="Foxlin.Aegir/secure-execution-receipt/v1",Service="aegir:service";
    private static readonly string[] Fields=["schema","receiptId","operationId","skillId","skillVersion","skillKey","manifestDigest","adapterId","adapterDigest",
        "originalIntentDigest","invocationDigest","inputDigest","tenantId","resourcePolicy","resourceAlias","agentId","humanAuthorityReference","rootGrantId","grantId",
        "lineageCommitment","policyCommitment","approvalId","enablementId","installationId","installationApprovalId","outcome","commitmentId","executedAtUtc","signedAtUtc","resultCommitment","algorithm","signingKeyId",
        "signerPrincipal","publicKeyFingerprint","trustProfile","clientDelivery","externalEffects"];
    private static readonly string[] Digests=["skillKey","manifestDigest","adapterDigest","originalIntentDigest","invocationDigest","inputDigest","humanAuthorityReference","lineageCommitment","policyCommitment","commitmentId","resultCommitment","publicKeyFingerprint"];
    public static AegirSecureExecutionArtifact Parse(JsonElement root)
    {
        Shape(root,"claims","signature");var c=root.GetProperty("claims");Shape(c,Fields);var copy=new SortedDictionary<string,string>(StringComparer.Ordinal);
        foreach(string n in Fields)copy.Add(n,c.GetProperty(n).ValueKind==JsonValueKind.String?c.GetProperty(n).GetString()!:throw new JsonException());
        Validate(copy);string signature=root.GetProperty("signature").GetString()??throw new JsonException();
        if(signature.Length is <1 or >8192)throw new JsonException();
        var artifact=new AegirSecureExecutionArtifact(new ReadOnlyDictionary<string,string>(copy),signature);
        if(JsonSerializer.SerializeToUtf8Bytes(artifact).Length>16384)throw new JsonException();return artifact;
    }
    public static byte[] CanonicalBytes(AegirSecureExecutionArtifact artifact)
    {
        var claims=Snapshot(artifact);Validate(claims);var utf8=new UTF8Encoding(false,true);
        using var stream=new MemoryStream();using var writer=new BinaryWriter(stream,utf8,true);
        foreach(string value in new[]{Domain}.Concat(Fields.Select(n=>claims[n])))
        {byte[] bytes=utf8.GetBytes(value);writer.Write(bytes.Length);writer.Write(bytes);}
        writer.Flush();return stream.ToArray();
    }
    public static AegirSecureReceiptVerification Verify(AegirSecureExecutionArtifact artifact,AegirReceiptTrustedServiceKey trusted,AegirReceiptExpectedContext expected)
    {
        try
        {
            if(artifact is null||trusted is null||expected is null||expected.OperationId==Guid.Empty||expected.RootGrantId==Guid.Empty||expected.GrantId==Guid.Empty||
                string.IsNullOrEmpty(expected.TenantId)||string.IsNullOrEmpty(expected.AgentId)||string.IsNullOrEmpty(expected.ResourceAlias))return new("MissingTrustedContext",false,false);
            var c=Snapshot(artifact);Validate(c);
            if(c["algorithm"]!="ML-DSA-65")return new("UnsupportedAlgorithm",false,false);
            if(!MLDsa.IsSupported)return new("UnsupportedPlatform",false,false);
            byte[] publicKey=(byte[])trusted.PublicKey.Clone();string fingerprint=Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
            if(trusted.PrincipalId!=Service||trusted.KeyId!=c["signingKeyId"]||trusted.KeyId!="mld1_"+fingerprint[..16]||fingerprint!=c["publicKeyFingerprint"])
                return new("UnknownTrustedKey",false,false);
            using MLDsa key=MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65,publicKey);
            var frozen=new AegirSecureExecutionArtifact(new ReadOnlyDictionary<string,string>(c),artifact.Signature);
            if(!key.VerifyData(CanonicalBytes(frozen),Convert.FromBase64String(artifact.Signature)))return new("InvalidSignature",false,false);
            var signed=DateTimeOffset.ParseExact(c["signedAtUtc"],"O",CultureInfo.InvariantCulture);
            if(signed<trusted.ActivatedAtUtc||trusted.RetiredAtUtc is{} retired&&signed>=retired||trusted.RevokedAtUtc is{} revoked&&signed>=revoked)
                return new("OutsideTrustedKeyLifetime",false,false);
            bool matches=c["operationId"]==expected.OperationId.ToString("N")&&c["tenantId"]==expected.TenantId&&c["agentId"]==expected.AgentId&&
                c["rootGrantId"]==expected.RootGrantId.ToString("N")&&c["grantId"]==expected.GrantId.ToString("N")&&c["resourceAlias"]==expected.ResourceAlias;
            return new(matches?"ValidHistoricalArtifactAndPinnedContext":"SignatureValidContextMismatch",true,matches);
        }
        catch(Exception e)when(e is ArgumentException or CryptographicException or FormatException or JsonException or InvalidOperationException or NullReferenceException)
        {return new("MalformedArtifactOrTrustContext",false,false);}
    }
    private static SortedDictionary<string,string> Snapshot(AegirSecureExecutionArtifact artifact)
    {if(artifact.Claims.Count!=Fields.Length)throw new JsonException();return new(artifact.Claims.ToDictionary(p=>p.Key,p=>p.Value),StringComparer.Ordinal);}
    private static void Validate(IReadOnlyDictionary<string,string> c)
    {
        if(c.Count!=Fields.Length||Fields.Any(n=>!c.TryGetValue(n,out var v)||v is null||v.Length is <1 or >512||v.Any(ch=>!char.IsAscii(ch)||char.IsControl(ch)))||
            c["schema"]!=Schema||c["skillId"]!="aegir.secure-execution.group-metadata"||c["adapterId"]!="foxlin.builtin.secure-execution-receipt.v1"||
            c["resourcePolicy"]!="group.administration.metadata.read"||c["outcome"]!="CommittedRead"||c["signerPrincipal"]!=Service||
            c["trustProfile"]!="aegir.c7.pinned-service-key/v1"||c["clientDelivery"]!="unproven"||c["externalEffects"]!="not-claimed"||
            Digests.Any(n=>!Hex(c[n]))||new[]{"receiptId","operationId","rootGrantId","grantId","approvalId","enablementId","installationId","installationApprovalId"}.Any(n=>!Guid.TryParseExact(c[n],"N",out var id)||id==Guid.Empty)||
            !Identifier(c["tenantId"])||!Identifier(c["agentId"])||c["resourceAlias"].Length>160||
            !DateTimeOffset.TryParseExact(c["executedAtUtc"],"O",CultureInfo.InvariantCulture,DateTimeStyles.None,out var executed)||executed.Offset!=TimeSpan.Zero||
            !DateTimeOffset.TryParseExact(c["signedAtUtc"],"O",CultureInfo.InvariantCulture,DateTimeStyles.None,out var signed)||signed.Offset!=TimeSpan.Zero||executed>signed)throw new JsonException();
    }
    private static bool Hex(string s)=>s.Length==64&&s.All(c=>c is >= '0'and <= '9'or >= 'a'and <= 'f');
    private static bool Identifier(string s)=>s.Length is >=1 and <=128&&s.All(c=>char.IsAsciiLetterOrDigit(c)||c is '_'or'-'or'.'or':');
    private static void Shape(JsonElement r,params string[] names)
    {if(r.ValueKind!=JsonValueKind.Object)throw new JsonException();var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var p in r.EnumerateObject())if(!names.Contains(p.Name,StringComparer.Ordinal)||!seen.Add(p.Name))throw new JsonException();if(seen.Count!=names.Length)throw new JsonException();}
}
