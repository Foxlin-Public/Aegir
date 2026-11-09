# Aegir Security Java source package

Foxlin Industries. Version `0.1.1-beta.1` is retained. This is local unreleased
source, not a Maven Central artifact. Use the existing source build with an
installed JDK 11 or later; no package download is required by the native tests.

```powershell
./scripts/test-authorization.ps1
```

```java
// Endpoint and developer credential come from host-owned private configuration.
try (AegirSecurityClient client = new AegirSecurityClient(
        privateApiBaseUrl, null, privateDeveloperCredential)) {
    SecurityModels.ScanIdentityResult scan = client.scanIdentity(subjectId);
    // A security report never supplies a cached application-authorization grant.
}
```

The seven retained operations are `scanIdentity`, `getIdentityGraph`,
`getIdentityGraphJson`, `getExposureSummary`, `performAction`, `reverseAction`,
and `getActionHistory`. Existing signatures/models remain; the client now
implements `AutoCloseable`. Configuration-key constructor parameters remain for
source compatibility and are ignored on these identity-bearing operations.

Read [LEGACY-SECURITY-HARDENING.md](LEGACY-SECURITY-HARDENING.md) for transport
compatibility changes and the explicit trusted-host custom adapter boundary.
Read [AUTHORIZATION-INTEGRATION.md](AUTHORIZATION-INTEGRATION.md) for canonical
fresh application checks, password/MFA exchange and durable event reconciliation.

`AegirSecurityError` keeps status/code/typed-code/correlation/body getters. Arbitrary
upstream body content is discarded; public error types remain. Diagnostics omit
subject paths, reversal reasons, credentials and raw server messages.

The existing budget defaults remain 25 scans, 50 lookups and 10 graph rebuilds per
60 seconds. In-memory budgets/A2A are local helpers. Retired keyless sign methods
still throw and verify methods return false. `computePayloadDigest` remains SHA256
over exact bytes and supplies no authentication. Unsigned envelopes supply only
integrity; non-null signature envelopes remain unsupported. This repair changes
no cryptographic algorithm, package metadata or publication state.
