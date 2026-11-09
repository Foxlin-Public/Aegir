# Aegir Security Model v0.1.1-beta.1

Status: Beta-1 documentation baseline.

## Identity Graph Model

The identity graph represents a subject and the trust context around that subject. A graph snapshot contains:

- `graphId`: stable graph identifier for the returned snapshot.
- `generatedAtUtc`: ISO-8601 UTC timestamp.
- `nodes`: identities, applications, credentials, devices, policy scopes, audit anchors, challenges, tokens, and external services.
- `edges`: relationships such as ownership, issuance, registration, authorization, scoping, usage, derivation, approval, revocation, anchoring, connection, and observation.
- `scores`: exposure, trust, and connection-clarity scores.
- `metadata`: implementation-defined key/value context.

The graph model is deliberately descriptive. Beta-1 SDKs expose it as a read model and do not expose host-only mutation APIs.

## Exposure Model

Exposure summaries convert graph state into actionable findings. Each `ExposureFinding` includes a stable finding id, category, severity, summary, optional node/edge references, and metadata.

Beta-1 categories:

- `WeakConnection`
- `UnknownConnection`
- `StaleCredential`
- `HighRiskLinkage`

Beta-1 severities:

- `Low`
- `Medium`
- `High`

## Safe Envelope Model

Local safe envelopes compare an unkeyed SHA-256 digest with canonical plaintext. They authenticate no issuer. An envelope contains:

- `envelopeId`
- `payloadType`
- `canonicalPayload`
- `payloadHash`
- `createdAtUtc`
- optional `signatureEnvelope`

Validation recomputes the hash from `canonicalPayload`. If the recomputed hash does not match `payloadHash`, validation returns `payload_hash_mismatch`. Any non-null signature envelope returns `unsupported_signature`. A matching unsigned record returns `integrity_only`, with `isAuthenticated=false`.

## What Aegir Actually Uses

Server-side, Beta-1 is post-quantum throughout. None of it runs in the SDK; the SDK's job is to
call the API and relay what it returns.

| Concern | Algorithm | Where |
|---|---|---|
| Payload confidentiality, agent to agent | **ML-KEM-768** key establishment + **AES-256-GCM** | `sendAgentMessage` / `receiveAgentMessage` |
| Origin of a protected message | **ML-DSA-65** signature over the authenticated header | same |
| Transaction receipts | **ML-DSA-65** | `getTransactionReceipt` / `verifyTransactionReceipt` |
| Device handoff proof | **ML-DSA-65** against the device's enrolled public key | Aegir API |
| Access tokens | HS256 JWT | `getToken` |
| Passwords | PBKDF2-SHA256, 210k iterations | Aegir Web host |

Two claims worth keeping separate: **TLS protects the network hop; the Aegir envelope protects
the payload inside it.** Neither is a substitute for the other, and neither is described as the
other.

A protected message is bound to its transaction in three independent places - the signature, the
key-derivation context and the AEAD additional data - so it cannot be moved to a different
transaction, sender, recipient or action. Relay the envelope unchanged.

## Retired Portable Trust-Core Helpers

AEG-RC1-R004 removes the old keyless digest implementation. The six old sign/verify symbols
remain deprecated compatibility stubs: sign always throws (Go panics), verify always returns
false. Standard `computePayloadDigest` hashes bytes using SHA-256 and authenticates nothing.
See [the compatibility contract](cryptographic-contracts-rc1.md) for each language's symbols,
intentional behavior changes, hosted alternatives and native/PQC limitations.

## Budgeting And Operational Controls

Budget envelopes enforce per-subject rolling-window limits. The canonical `BudgetEnvelopeOptions` shape is:

| Field | Default |
| --- | ---: |
| `identityScanLimit` / `IdentityScanLimit` | `25` |
| `externalLookupLimit` / `ExternalLookupLimit` | `50` |
| `connectionGraphRebuildLimit` / `ConnectionGraphRebuildLimit` | `10` |
| `windowMs` / `WindowMS` | `60000` |

Budget envelope records expose `controlType`, `subjectKey`, `windowStartedAtUtc`, `windowEndsAtUtc`, `limit`, `consumed`, `remaining`, and `isExhausted`. Exhaustion is surfaced through the language-specific `BudgetExhaustedException`, `BudgetExhaustedError`, or equivalent error value.

## Diagnostics And Audit Behavior

SDK diagnostics are the public Beta-1 audit and observability hook. Clients emit:

- Log entries for request start, completion, and error.
- Metric events for request duration/status/error-code dimensions.
- Trace events for request lifecycle phases.

Diagnostics event shapes include operation names, correlation ids when present, timestamps, and metadata/dimensions. Host-side audit ledger and persistence internals are not exposed as public SDK APIs in Beta-1.

## Error Model

Every SDK maps HTTP/API failures to a language-specific security client error that carries status, typed error code, correlation id when available, and response body/payload when available.

Canonical `AegirErrorCode` values:

- `invalid_request`
- `unauthorized`
- `forbidden`
- `not_found`
- `conflict`
- `rate_limited`
- `budget_exhausted`
- `server_error`
- `transport_error`
- `unknown_error`
