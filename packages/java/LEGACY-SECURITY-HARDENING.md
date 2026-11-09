# Retained Java SDK transport security

Foxlin Industries. Local unreleased source, not a published Maven artifact.

`JsonSupport` now delegates to the nonexecuting strict JSON parser. No script
engine or evaluator parses responses or fixtures. Decimal values preserve the
existing typed BigDecimal model. Public method signatures, typed enum wire names,
package version and cryptographic behavior remain unchanged.

Deliberate security behavior changes reject HTTP, redirects, malformed or
mismatched responses and unmarked opaque adapters. The configuration-key argument
remains but is never transmitted to these identity-bearing security routes. The
seven retained endpoint families require genuine server authentication and current
server authorization. Graph/action/exposure DTOs never authorize application work.

The default path owns a standard JDK HTTPS client with TLS 1.2 or later, normal
certificate/hostname verification, no redirects, cookies or proxies, and a bounded
executor. A supplied concrete JDK HttpClient is used as a compatibility input;
a fresh safe-policy client is built rather than inheriting unsafe redirect/TLS
or shared executor state. The supplied instance and JVM defaults remain unchanged.
Its custom roots, client certificates, proxy, cookies and callbacks are not copied.
An arbitrary HttpClient subclass is rejected unless the additive constructor's
`trustHttpAdapter` argument explicitly opts in to trusted host code. Such an
adapter can bypass wire TLS, redirect or cancellation rules and is the host's
responsibility; opt-in is not security certification.

`pinnedLoopbackDevelopment` permits an exact SHA256 of the certificate DER only
for an HTTPS localhost/literal loopback origin, with host and certificate validity
checks. It changes no JVM-wide trust. Keep this factory restricted to synthetic
local development and keep real credentials outside source/logs.

Each request has a deadline (15 seconds by default, maximum 30 seconds through the
explicit factory). Thread interruption cancels the pending request. `close`
cancels pending futures, shuts down the owned executor and releases the client
reference; owned executor shutdown is tested. JDK 11 exposes no HttpClient.close:
its internal daemon selector cleanup remains JVM-managed after reference release.
The host must close clients and never reuse a closed instance. Opaque host adapters
must implement their own bounded cancellation/resource policy.

Responses require exactly HTTP 200 and one exact JSON Content-Type, with optional
UTF8 charset. Reads stop at 1 MiB before parsing. Invalid UTF8, escaped Unicode,
duplicate/case-variant names, trailing/malformed documents, depth beyond 32 and
excessive collections fail closed. Required model fields use exact spelling and
types; identity/action values bind to the requested operation. Bounded additive
optional DTO properties remain compatible and confer no authority. Model arrays
are bounded to 10,000 and metadata maps to 1,000 entries. Unknown enum values do
not silently default.

Upstream error bodies/messages are not retained in exceptions or causes. Codes
use the finite SDK vocabulary. Correlation identifiers are bounded and reject
configured credential strings and their secret components. Diagnostics contain
operation/status metadata, not subject paths or reversal reasons. Explicitly
reading private host configuration can still disclose it; no formatter can make
host code trustworthy by itself.

Native synthetic TLS/parser tests and genuine Aegir backend acceptance are
separate. A pre-write server check does not create an atomic transaction fence
across an independent application database. The separate canonical integration
still requires fresh checks and startup/reconnect snapshot reconciliation.

## Current server enum compatibility

The retained public models expose enum names. The current security-report server
serializes its six C# enums as 1-based integers. The transport accepts only exact
known integer values or known names, normalizes them to the existing named model,
and sends a known numeric `actionType` for the real action endpoint. Fractional,
unknown and out-of-range values fail closed. Direct public model serialization
keeps its historical string shape; use client methods for the server wire format.

A genuine-server smoke example reads a private JSON file containing `apiBaseUrl`,
`developerKey`, `subjectId`, optional loopback `certificateSha256` and `timeoutMs`.
It exercises scan, graph, graph JSON, exposure, RequestClarity action, reversal and
history. It prints only operation success booleans. RequestClarity creates
synthetic audit data; use only the approved local synthetic dataset.

```powershell
java -cp target/classes cloud.foxlin.aegir.security.LegacySecurityScenario C:/private/legacy-security.json
```

## Windows replacement availability

Observed local NTFS access-denied/sharing failures are retained in D2 evidence.
The journal may retry only the same already-flushed atomic replacement during a
bounded 200 ms retry window while retaining its owner lock and journal monitor.
It never repeats the transaction, replaces the temporary content, alters ACLs,
falls back to non-atomic writes or advances in-memory state before success.
Nonsharing errors and exhausted retries still fail closed. Ordinary filesystem
syscall scheduling and hardware/power-loss behavior remain outside this bound.

## Diagnostic callback lifetime

The same operation deadline covers diagnostics and the owned transport. A blocked
hook cannot extend the caller's wait or cause a result to be returned after
cancellation, deadline expiry or client close. Completion hooks are followed by
a final lifetime check before returning/adopting a result. Ordinary hook failures
are sanitized and best effort; they supply no authority.

Arbitrary host code cannot safely be killed. A global budget of four callback
workers, with no unbounded queue, bounds stranded callbacks across clients.
When that budget is occupied, optional diagnostics are skipped. Cancellation or
close stops waiting for an uncooperative callback; Java interrupts best effort.
The host callback may still finish its own external side effects later, which the
SDK cannot undo. Hosts must keep callbacks bounded and avoid using diagnostic
hooks for required business commits or authoritative audit persistence.
