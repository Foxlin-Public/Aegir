# Aegir Security Go source package

Foxlin Industries. Version `0.1.1-beta.1` is retained. This is local, unreleased
source; the module is not published or resolvable through `go get`.

Build/test inside this directory with an installed Go toolchain (minimum 1.22):

```powershell
$env:GOTOOLCHAIN='local'
$env:GOPROXY='off'
$env:GOSUMDB='off'
go test -count=1 ./...
```

The module has no third-party dependencies. For a standalone example, create a
local module and use a local `replace` directive pointing to this source tree.
Do not put credentials in that module or commit private configuration.

```go
// Load endpoint and developer credential from host-owned private configuration.
client := aegirsecurity.NewAegirSecurityClientWithOptions(aegirsecurity.ClientOptions{
    BaseURL: privateAPIBaseURL, // HTTPS; include any deployment prefix such as /apis
    DeveloperKey: privateDeveloperCredential,
})
defer client.Close()
scan, err := client.ScanIdentityContext(ctx, subjectID)
if err != nil { return err }
// This is an authorized security report, never a cached application-access grant.
_ = scan
```

Retained operations are `ScanIdentity`, `GetIdentityGraph`,
`GetIdentityGraphJSON`, `GetExposureSummary`, `PerformAction`, `ReverseAction`,
and `GetActionHistory`. Their signatures remain available; additive `...Context`
variants accept caller cancellation. Every request also has a bounded timeout:
15 seconds by default, configurable through `ClientOptions.Timeout`, maximum 30
seconds. `Close` cancels active work and closes owned idle connections. Reuse
a client for its lifetime and close it when the host stops using it.

Read [LEGACY-SECURITY-HARDENING.md](LEGACY-SECURITY-HARDENING.md) before migrating
an injected transport. The transitional configuration-key argument/member remains
for source compatibility but is ignored on these identity-bearing operations.
Use the separate [authorization integration](AUTHORIZATION-INTEGRATION.md) for
fresh application authorization, password/MFA exchange and event reconciliation.

HTTP failures retain `*AegirSecurityError` and its public fields, but arbitrary
upstream `Body` content is no longer retained. Error codes use the finite SDK
vocabulary. Diagnostics contain operation/status metadata, never subject paths,
reversal reasons, credentials or raw response text. `ClientOptions` normal
formatting and JSON serialization redact private values; hosts must still keep
individual credential fields private.

The existing in-memory budget and A2A helpers are local development helpers.
Their defaults remain 25 scans, 50 lookups and 10 graph rebuilds per 60 seconds.
They do not supply server authorization. Retired keyless sign helpers still panic,
verify helpers still return false, and `ComputePayloadDigest` remains standard
SHA256 over exact bytes. Unsigned envelopes provide integrity only; no non-null
signature is accepted as authority. No cryptographic algorithm or package version
is changed by this repair.
