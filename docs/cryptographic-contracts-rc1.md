# RC1 cryptographic compatibility contract

Foxlin Industries · AEG-RC1-R004 · unreleased source version `0.1.2-beta.1`.

This describes the reviewed source checkout. It does not change packages already published to
registries, publish an SDK, or establish native/hybrid production interoperability.

## Retired keyless authority

The challenge, proof-receipt and identity-token `sign*Payload` / `verify*Payload` helpers never
had signing keys. Their old deterministic values authenticated neither issuer nor identity.
Their original names remain as deprecated compatibility stubs, with an intentional behavioral
break: signing always throws (`Error`, `NotImplementedError`, `UnsupportedOperationException`;
Go panics because its retained return signature has no error channel), and verification always
returns `false`, even for previously matching values. The old custom digest algorithm is removed.

These functions must not sign an enrolled device challenge, generate a receipt, establish agent
identity, or authorize anything. Migrate security-bearing consumers to the existing server's
keyed contracts. There is no SDK-local replacement signing authority or private-key export.

| Purpose | Node / Java | Python | Go | Actual guarantee |
|---|---|---|---|---|
| Retired challenge sign | `signChallengePayload` | `sign_challenge_payload` | `SignChallengePayload` | Unsupported; throws/panics |
| Retired challenge verify | `verifyChallengePayload` | `verify_challenge_payload` | `VerifyChallengePayload` | Always rejects |
| Retired receipt sign | `signProofReceiptPayload` | `sign_proof_receipt_payload` | `SignProofReceiptPayload` | Unsupported; throws/panics |
| Retired receipt verify | `verifyProofReceiptPayload` | `verify_proof_receipt_payload` | `VerifyProofReceiptPayload` | Always rejects |
| Retired identity sign | `signIdentityTokenPayload` | `sign_identity_token_payload` | `SignIdentityTokenPayload` | Unsupported; throws/panics |
| Retired identity verify | `verifyIdentityTokenPayload` | `verify_identity_token_payload` | `VerifyIdentityTokenPayload` | Always rejects |
| SHA-256 bytes | `computePayloadDigest` | `compute_payload_digest` | `ComputePayloadDigest` | Lowercase SHA-256 hex; hash only |
| Local envelope create | `createSafeEnvelope` | `create_safe_envelope` | `CreateSafeEnvelope` | Local plaintext plus unkeyed SHA-256 |
| Local envelope validate | `validateSafeEnvelope` | `validate_safe_envelope` | `ValidateSafeEnvelope` | Integrity comparison only |

Java methods live on `PortableSecurity`. The .NET source equivalents use
`AegirPortableSecurity.ComputePayloadDigest` and PascalCase retired names. Only source-level
compatibility is described; installed package versions must be checked against `sdk-manifest.json`.
Java and Go remain source-only, unpublished reference packages.

## Local integrity utilities

`computePayloadDigest` hashes the exact supplied bytes, including empty bytes, into lowercase
SHA-256 hex. It does no JSON normalization, signing, encryption, key lookup or verification.
For a UTF-8 string, callers must encode UTF-8 explicitly. Different JSON property order or whitespace
produces different bytes and therefore a different digest. This is not an authority wire protocol.

`SafeEnvelopeRecord` retains its existing payload hash representation. A matching unsigned record
returns `isValid=true`, `reason="integrity_only"`, and `isAuthenticated=false`. The authentication
flag is exposed as an accessor in Java/Python and a field in Node/Go. A hash mismatch returns
`payload_hash_mismatch`. Every non-null legacy `signatureEnvelope` is rejected as
`unsupported_signature`, regardless of key identifier, algorithm label or supplied signature bytes.
The DTOs remain for decoding historical records, not as accepted proofs. A digest and its payload
can both be substituted by an adversary, so a successful local comparison grants no permissions.

Historical local-envelope formats are not one cryptographic wire contract: .NET payload hashes
are uppercase hex, while these four language helpers use lowercase hex. The .NET legacy algorithm
descriptor carries `AlgorithmId`, `AlgorithmVersion`, `ProtectionMode` and `IntendedKeyUse`;
the four language DTOs carry `algorithmId` and `hybrid`. These differences remain for source
compatibility. They do not affect the new lowercase SHA-256 byte-digest utility, and they must
not be presented as signed-envelope or keyed cross-language interoperability.

`InMemoryAgentToAgentProtocol` is a local development queue. Its unsigned receipt acceptance is
local delivery only; it provides no enrolled identity, confidentiality, transaction authorization,
nonce replay protection or cross-tenant authentication. It rejects messages claiming unsupported
portable signatures. Use the hosted message methods for protected agent messages.

## Genuine authority stays on the existing runtime

The Node/Python HTTP clients expose `getTransactionReceipt`, `verifyTransactionReceipt`,
`sendAgentMessage` and `receiveAgentMessage`. These relay the runtime's existing keyed receipt and
protected-message contracts. The twelve-tool MCP wrapper forwards receipt verification to the
server and returns its result; it does not run portable verification. Java/Go source in this
repository has no equivalent receipt or protected-message HTTP methods; do not invent such calls.

The server's ML-DSA-65 verification, key identifier/algorithm selection, historical-key handling,
transaction/tenant binding, and ML-KEM-768/AES-256-GCM protected envelope remain separate from
these local digest utilities. Preserve signed field values and canonical payload bytes when
relaying receipts and protected envelopes. Normal JSON transport serialization is allowed;
the runtime's defined canonical form determines the signature bytes, rather than JSON property
order on the transport. Device challenges require the canonical server-issued context and the enrolled
device's genuine authorized key; the retired helpers cannot provide it.

AEG-RC1-W01-006 remains the separate architecture requirement for genuine native/Rust keyed-PQC
production interoperability. Shared SHA-256 vectors and rejected historical keyless artifacts
demonstrate integrity-utility compatibility and fail-closed behavior only, not PQC interoperability.

## Validation and migration

All four language source packages and their public repository copies execute shared empty,
ASCII, UTF-8 and binary SHA-256 vectors. Tests reject historical keyless values, empty/malformed
proofs, fabricated algorithm/key metadata, and signed local queue messages. Existing server
keyed positive and adversarial verification evidence belongs to the runtime test suite.

Migration requires removing every security use of a retired helper, keeping digest comparisons
out of identity/authorization decisions, and treating `integrity_only` as a diagnostic result.
Do not fall back to accepting an unsigned local envelope after a signed record is rejected.
