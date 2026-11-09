# Retained Go SDK transport security

Foxlin Industries. Local unreleased source; no package publication implied.

The existing public methods and typed wire models remain. Deliberate security
corrections reject cleartext HTTP, malformed or contradictory response contracts,
redirects and unmarked opaque HTTP adapters. The legacy configuration-key member
is retained but no configuration secret is attached to identity-bearing routes.
Invalid configuration is remembered by the constructor and operations return a
sanitized error before transport use, preserving the constructor signature.

The client owns a copy of a supplied concrete `http.Client` and a fresh concrete
transport. It does not mutate the supplied instance or `http.DefaultClient` /
`http.DefaultTransport`. Redirect following, cookie storage, proxies and custom
network dialing are not inherited. TLS 1.2 or later and ordinary certificate /
host validation apply. A caller's private RootCAs can be retained; insecure TLS
verification flags, custom certificate callbacks and client certificate hooks are
rejected. Configure those explicitly in a separately trusted host adapter only
when the host has reviewed the extra trust boundary.

An opaque `HTTPDoer` or `RoundTripper` is rejected by default. `TrustHTTPAdapter`
is an explicit opt-in to trusted host code. An opted-in adapter can ignore request
contexts, follow redirects internally, manufacture responses or bypass wire TLS;
the SDK cannot certify that behavior. The adapter must enforce its own bounded
execution, TLS and redirect rules. Typed nil adapters still fail closed. Opt-in
never turns a local fixture into evidence of real Aegir authority.

For synthetic local development only, `CertificateSHA256` is an exact SHA256 of
the leaf certificate DER. It requires a literal HTTPS loopback/localhost origin,
matching certificate host and current validity period. It never changes global
trust. A pin is not allowed for a remote host or opaque custom adapter.

Responses require exactly HTTP 200, a single exact `application/json` media type,
UTF8 JSON and at most 1 MiB of wire body. A declared charset must be UTF8.
Streaming reads stop at the bound. Parsing rejects duplicate or case-variant
properties, malformed/trailing documents, invalid Unicode, depth beyond 32 and
collections beyond the parser limits. The known DTO fields are required with
exact casing and types; optional additional response fields are tolerated as
bounded data. Model arrays are bounded to 10,000 and metadata maps to 1,000
entries. Identity/action fields bind to the requested subject/action; unknown
enums are rejected. No missing value becomes an implicit permission or identity.

This retained security-report family has no authority-bearing local permit.
Graphs, exposure reports and action records never replace the canonical current
application-authorization check. An HTTP pre-write check also cannot create an
atomic commit fence in a separate application database.

Error bodies are discarded, error codes are from the finite SDK vocabulary, and
correlation values are bounded identifiers with configured credential/components
excluded. Logs/traces omit request paths, query values and subject identifiers.
No arbitrary upstream error is returned as a diagnostic message or cause.

`...Context` operations add cancellation without removing original methods.
`Timeout` defaults to 15 seconds and cannot exceed 30 seconds. `Close` cancels
in-flight standard transport requests and releases owned idle connections.
The host must not share a closed client. Formatting/JSON redaction protects common
accidental logging; it cannot prevent a host deliberately reading public fields.

Java/Go native synthetic TLS tests validate these adapters. Actual Aegir host
integration is separate evidence. Retired keyless trust helpers remain unchanged
and fail closed; hash-only integrity remains unauthenticated.

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
go build -o bin/legacy-security-scenario.exe ./cmd/legacy-security-scenario
./bin/legacy-security-scenario.exe C:/private/legacy-security.json
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
