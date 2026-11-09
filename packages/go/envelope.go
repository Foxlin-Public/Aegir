package aegirsecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TrustCoreAlgorithmDescriptor is a legacy metadata DTO; it confers no authority.
type TrustCoreAlgorithmDescriptor struct {
	AlgorithmID string `json:"algorithmId"`
	Hybrid      bool   `json:"hybrid"`
}

// TrustCoreSignatureEnvelope is retained for decoding legacy records; portable validation rejects it.
type TrustCoreSignatureEnvelope struct {
	KeyID          string                       `json:"keyId"`
	Algorithm      TrustCoreAlgorithmDescriptor `json:"algorithm"`
	SignatureBytes []byte                       `json:"signatureBytes"`
}

// SafeEnvelopeRecord is a local SHA-256 integrity container, not an authenticated signed envelope.
type SafeEnvelopeRecord struct {
	EnvelopeID        string                      `json:"envelopeId"`
	PayloadType       string                      `json:"payloadType"`
	CanonicalPayload  string                      `json:"canonicalPayload"`
	PayloadHash       string                      `json:"payloadHash"`
	CreatedAtUTC      string                      `json:"createdAtUtc"`
	SignatureEnvelope *TrustCoreSignatureEnvelope `json:"signatureEnvelope,omitempty"`
}

// SafeEnvelopeValidationResult reports whether the supplied safe envelope is valid.
type SafeEnvelopeValidationResult struct {
	IsAuthenticated bool   `json:"isAuthenticated"` // Always false for portable validation.
	IsValid         bool   `json:"isValid"`
	Reason          string `json:"reason"`
}

// CreateSafeEnvelope creates a deterministic safe envelope for the supplied payload.
func CreateSafeEnvelope(payloadType, canonicalPayload string, signatureEnvelope *TrustCoreSignatureEnvelope) (*SafeEnvelopeRecord, error) {
	if payloadType == "" {
		return nil, errors.New("payload type is required")
	}

	if canonicalPayload == "" {
		return nil, errors.New("canonical payload is required")
	}

	return &SafeEnvelopeRecord{
		EnvelopeID:        generateRuntimeID("env"),
		PayloadType:       payloadType,
		CanonicalPayload:  canonicalPayload,
		PayloadHash:       computePayloadHash(canonicalPayload),
		CreatedAtUTC:      time.Now().UTC().Format(time.RFC3339),
		SignatureEnvelope: signatureEnvelope,
	}, nil
}

// ValidateSafeEnvelope compares a payload hash only and rejects unsupported signature claims.
func ValidateSafeEnvelope(envelope SafeEnvelopeRecord) SafeEnvelopeValidationResult {
	if envelope.PayloadHash != computePayloadHash(envelope.CanonicalPayload) {
		return SafeEnvelopeValidationResult{
			IsValid: false,
			Reason:  "payload_hash_mismatch",
		}
	}

	if envelope.SignatureEnvelope != nil {
		return SafeEnvelopeValidationResult{
			IsValid: false,
			Reason:  "unsupported_signature",
		}
	}

	return SafeEnvelopeValidationResult{
		IsValid: true,
		Reason:  "integrity_only",
	}
}

// ComputePayloadDigest returns lowercase SHA-256 hex of exact bytes. It does not authenticate anyone.
func ComputePayloadDigest(payload []byte) string {
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}

// Deprecated: keyless authority is unsupported. This retained signature always panics.
func SignChallengePayload(payload []byte) []byte {
	panic("Keyless signing is unsupported. Use an authorized keyed signing contract.")
}

// Deprecated: keyless authority is unsupported. This always rejects, including historical digests.
func VerifyChallengePayload(payload []byte, signature []byte) bool {
	return false
}

// Deprecated: keyless authority is unsupported. This retained signature always panics.
func SignProofReceiptPayload(payload []byte) []byte {
	panic("Keyless signing is unsupported. Use an authorized keyed signing contract.")
}

// Deprecated: keyless authority is unsupported. This always rejects, including historical digests.
func VerifyProofReceiptPayload(payload []byte, signature []byte) bool {
	return false
}

// Deprecated: keyless authority is unsupported. This retained signature always panics.
func SignIdentityTokenPayload(payload []byte) []byte {
	panic("Keyless signing is unsupported. Use an authorized keyed signing contract.")
}

// Deprecated: keyless authority is unsupported. This always rejects, including historical digests.
func VerifyIdentityTokenPayload(payload []byte, signature []byte) bool {
	return false
}

func computePayloadHash(canonicalPayload string) string {
	hash := sha256.Sum256([]byte(canonicalPayload))
	return hex.EncodeToString(hash[:])
}

func generateRuntimeID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
}
