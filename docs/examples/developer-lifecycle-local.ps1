# Copyright Foxlin Industries. Actual synthetic local HTTP lifecycle; no secret output.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$ApiBaseUri,
    [Parameter(Mandatory)][switch]$ConfirmSynthetic,
    [string]$CertificateSha256
)
$ErrorActionPreference = 'Stop'
if (-not $ConfirmSynthetic) { throw 'Synthetic local use must be confirmed.' }
if (-not $ApiBaseUri.IsAbsoluteUri -or $ApiBaseUri.Host -notin @('localhost', '127.0.0.1', '::1', '[::1]') -or
    $ApiBaseUri.Scheme -ne 'https' -or $ApiBaseUri.UserInfo -or $ApiBaseUri.Query -or $ApiBaseUri.Fragment) {
    throw 'Supply an HTTPS loopback API base URI, such as https://127.0.0.1:54151/apis/.'
}
if ($CertificateSha256 -and $CertificateSha256 -notmatch '\A[0-9a-fA-F]{64}\z') { throw 'The optional local certificate pin must be an exact SHA256 hex digest.' }
$developerCredential = [Environment]::GetEnvironmentVariable('AEGIR_SYNTHETIC_DEVELOPER_KEY')
if ([string]::IsNullOrWhiteSpace($developerCredential)) { throw 'Set AEGIR_SYNTHETIC_DEVELOPER_KEY in the process environment; do not place it in source.' }
if (-not ('Foxlin.Aegir.LocalExampleTransport' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
namespace Foxlin.Aegir {
    public static class LocalExampleTransport {
        public static HttpClient Create(Uri endpoint, string digest) {
            if (endpoint == null || endpoint.Scheme != "https" || !endpoint.IsLoopback)
                throw new ArgumentException("HTTPS loopback endpoint required.");
            var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
            if (!String.IsNullOrEmpty(digest)) {
                if (digest.Length != 64) throw new ArgumentException("Exact SHA256 pin required.");
                var expected = new byte[32];
                for (int i = 0; i < expected.Length; i++)
                    expected[i] = Byte.Parse(digest.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
                // A compiled delegate avoids PowerShell worker-thread/runspace callbacks.
                handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) => {
                    if (certificate == null || request.RequestUri == null || !request.RequestUri.IsLoopback ||
                        request.RequestUri.Scheme != "https" || request.RequestUri.Host != endpoint.Host ||
                        (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 ||
                        DateTime.UtcNow < certificate.NotBefore.ToUniversalTime() || DateTime.UtcNow > certificate.NotAfter.ToUniversalTime()) return false;
                    using (var sha = SHA256.Create()) {
                        byte[] actual = sha.ComputeHash(certificate.RawData);
                        int mismatch = actual.Length ^ expected.Length;
                        for (int i = 0; i < expected.Length; i++) mismatch |= actual[i] ^ expected[i];
                        return mismatch == 0;
                    }
                };
            }
            return new HttpClient(handler);
        }
    }
}
'@
}
$client = [Foxlin.Aegir.LocalExampleTransport]::Create($ApiBaseUri, $CertificateSha256)
$client.Timeout = [TimeSpan]::FromSeconds(30)
$client.BaseAddress = [uri]($ApiBaseUri.AbsoluteUri.TrimEnd('/') + '/')
$applicationId = 'd2_example_' + [guid]::NewGuid().ToString('N')
$createdApplication = $false
$issuedKeyIds = [System.Collections.Generic.List[string]]::new()
$agentId = $null
function Invoke-LocalAegir([string]$Method, [string]$Path, [object]$Body = $null) {
    $message = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), 'v1/' + $Path.TrimStart('/'))
    try {
        $message.Headers.Add('X-Aegir-Developer-Key', $developerCredential)
        if ($null -ne $Body) {
            $message.Content = [System.Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 10 -Compress), [Text.Encoding]::UTF8, 'application/json')
        }
        $response = $client.SendAsync($message).GetAwaiter().GetResult()
        try {
            if (-not $response.IsSuccessStatusCode) { throw ('Local synthetic lifecycle request failed with HTTP ' + [int]$response.StatusCode + '. Inspect current state before retrying.') }
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ($text) { return $text | ConvertFrom-Json }
        } finally { $response.Dispose() }
    } finally { $message.Dispose() }
}
try {
    $application = Invoke-LocalAegir POST 'developer/applications' @{ applicationId = $applicationId; environmentId = 'staging'; displayName = 'Synthetic D2 lifecycle example' }
    $createdApplication = $true
    $null = Invoke-LocalAegir GET 'developer/applications'
    $issued = Invoke-LocalAegir POST 'developer/keys' @{ displayName = 'Synthetic example key' }
    $issuedKeyIds.Add($issued.devKeyId)
    $rotated = Invoke-LocalAegir POST ('developer/keys/' + $issued.devKeyId + '/rotate') @{}
    $issuedKeyIds.Add($rotated.devKeyId)
    $null = Invoke-LocalAegir POST ('developer/keys/' + $rotated.devKeyId + '/revoke')
    $incident = Invoke-LocalAegir POST 'developer/keys' @{ displayName = 'Synthetic compromise example' }
    $issuedKeyIds.Add($incident.devKeyId)
    $null = Invoke-LocalAegir POST ('developer/keys/' + $incident.devKeyId + '/compromise') @{ reason = 'Synthetic example only' }
    $null = Invoke-LocalAegir GET 'developer/keys'
    $agent = Invoke-LocalAegir POST 'agents' @{ displayName = 'Synthetic independent agent'; applicationId = $applicationId; scopes = @('transaction:read') }
    $agentId = $agent.agent.agentId
    $null = Invoke-LocalAegir GET 'agents'
    $null = Invoke-LocalAegir GET ('agents/' + $agentId)
    $null = Invoke-LocalAegir PUT ('agents/' + $agentId + '/scopes') @{ scopes = @('transaction:read', 'transaction:write') }
    $agentReplacement = Invoke-LocalAegir POST ('agents/' + $agentId + '/credentials/rotate')
    $null = Invoke-LocalAegir POST ('agents/' + $agentId + '/revoke')
    $null = Invoke-LocalAegir DELETE ('developer/applications/' + $applicationId)
    $createdApplication = $false
    [pscustomobject]@{ Status = 'Completed'; ApplicationId = $applicationId; AgentId = $agentId; DistinctModeledOperations = 14; SecretsPrinted = $false }
} finally {
    # Only retire resources created by this invocation. Never change the supplied source key.
    if ($agentId) { try { $null = Invoke-LocalAegir POST ('agents/' + $agentId + '/revoke') } catch { Write-Warning 'Synthetic agent cleanup requires current-state inspection.' } }
    foreach ($id in $issuedKeyIds) { try { $null = Invoke-LocalAegir POST ('developer/keys/' + $id + '/revoke') } catch { } }
    if ($createdApplication) { try { $null = Invoke-LocalAegir DELETE ('developer/applications/' + $applicationId) } catch { Write-Warning 'Synthetic application cleanup requires current-state inspection.' } }
    $client.Dispose()
    $developerCredential = $null
}
