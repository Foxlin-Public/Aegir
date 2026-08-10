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

Safe envelopes protect canonical payload integrity across SDKs. An envelope contains:

- `envelopeId`
- `payloadType`
- `canonicalPayload`
- `payloadHash`
- `createdAtUtc`
- optional `signatureEnvelope`

Validation recomputes the hash from `canonicalPayload`. If the recomputed hash does not match `payloadHash`, validation returns `payload_hash_mismatch`. If a signature envelope is present without required signature bytes, validation returns `signature_missing`.

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

## Portable Trust-Core Helpers (deprecated)

Beta-1 still exposes portable helper functions in every SDK: challenge, proof-receipt and
identity-token payload signing and verification.

> **These helpers are not Aegir's cryptography.** They are a deterministic, **keyless**
> digest: anyone who knows the algorithm - and it is published here, in five languages - can
> produce a matching value. They therefore prove nothing about possession of a key, and they must
> not be used to authenticate anything or to establish integrity against an adversary.
>
> They exist for cross-language parity tests and local development fixtures, and are kept in
> Beta-1 only so existing callers keep compiling. Treat them as deprecated.


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
