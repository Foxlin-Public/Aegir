package aegirsecurity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestCreateSafeEnvelopeAndValidate(t *testing.T) {
	envelope, err := CreateSafeEnvelope("agent:test", `{"hello":"world"}`, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	result := ValidateSafeEnvelope(*envelope)
	if !result.IsValid {
		t.Fatalf("expected valid envelope, got %s", result.Reason)
	}
}

func TestValidateSafeEnvelopeDetectsTampering(t *testing.T) {
	envelope, err := CreateSafeEnvelope("agent:test", `{"hello":"world"}`, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	envelope.CanonicalPayload = `{"hello":"tampered"}`
	result := ValidateSafeEnvelope(*envelope)
	if result.IsValid {
		t.Fatalf("expected invalid envelope")
	}
	if result.Reason != "payload_hash_mismatch" {
		t.Fatalf("expected payload_hash_mismatch, got %s", result.Reason)
	}
}

func TestValidateSafeEnvelopeDetectsMissingSignatureBytes(t *testing.T) {
	envelope, err := CreateSafeEnvelope("agent:test", `{"hello":"world"}`, &TrustCoreSignatureEnvelope{
		KeyID: "key_123",
		Algorithm: TrustCoreAlgorithmDescriptor{
			AlgorithmID: "hybrid-beta1",
			Hybrid:      true,
		},
		SignatureBytes: []byte{},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	result := ValidateSafeEnvelope(*envelope)
	if result.IsValid {
		t.Fatalf("expected invalid envelope")
	}
	if result.Reason != "unsupported_signature" {
		t.Fatalf("expected unsupported_signature, got %s", result.Reason)
	}
}

func TestR004SharedSHA256VectorsIntegrityOnly(t *testing.T) {
	var vectors struct {
		SHA256 []struct{ Hex, Digest string } `json:"sha256"`
	}
	data, err := os.ReadFile("crypto-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.SHA256 {
		payload, err := hex.DecodeString(vector.Hex)
		if err != nil {
			t.Fatal(err)
		}
		if got := ComputePayloadDigest(payload); got != vector.Digest {
			t.Fatalf("SHA256 mismatch %s", got)
		}
	}
	if ComputePayloadDigest([]byte(`{"a":1,"b":2}`)) == ComputePayloadDigest([]byte(`{"b":2,"a":1}`)) {
		t.Fatal("changed serialization must change digest")
	}
}

func TestR004LegacyAuthorityFailsClosed(t *testing.T) {
	var vectors struct {
		Historical map[string]string `json:"historicalKeyless"`
	}
	data, err := os.ReadFile("crypto-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(vectors.Historical["payloadHex"])
	cases := []struct {
		name   string
		sign   func([]byte) []byte
		verify func([]byte, []byte) bool
	}{
		{"challenge", SignChallengePayload, VerifyChallengePayload},
		{"proofReceipt", SignProofReceiptPayload, VerifyProofReceiptPayload},
		{"identityToken", SignIdentityTokenPayload, VerifyIdentityTokenPayload},
	}
	for _, c := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("retired signer must panic")
				}
			}()
			c.sign(payload)
		}()
		legacy, _ := hex.DecodeString(vectors.Historical[c.name])
		for _, proof := range [][]byte{legacy, nil, {}, make([]byte, 64), append(append([]byte{}, legacy...), 1)} {
			if c.verify(payload, proof) {
				t.Fatal("retired verifier accepted authority")
			}
		}
	}
}

func TestR004PortableEnvelopeNeverAuthenticates(t *testing.T) {
	unsigned, err := CreateSafeEnvelope("test", "abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := ValidateSafeEnvelope(*unsigned)
	if !result.IsValid || result.IsAuthenticated || result.Reason != "integrity_only" {
		t.Fatalf("wrong integrity classification: %+v", result)
	}
	for _, algorithm := range []string{"ML-DSA-65", "hybrid-beta1", "", "invalid"} {
		for _, key := range []string{"unknown", "substituted-device", ""} {
			for _, proof := range [][]byte{nil, make([]byte, 64), make([]byte, 3309)} {
				signed, err := CreateSafeEnvelope("test", "abc", &TrustCoreSignatureEnvelope{KeyID: key, Algorithm: TrustCoreAlgorithmDescriptor{AlgorithmID: algorithm}, SignatureBytes: proof})
				if err != nil {
					t.Fatal(err)
				}
				result := ValidateSafeEnvelope(*signed)
				if result.IsValid || result.IsAuthenticated || result.Reason != "unsupported_signature" {
					t.Fatalf("accepted authority: %+v", result)
				}
			}
		}
	}
}

func TestR004InProcessQueueRejectsFabricatedSignature(t *testing.T) {
	queue := NewInMemoryAgentToAgentProtocol()
	message, err := queue.Send("agent:sender", "agent:recipient", "test", "abc", nil, &TrustCoreSignatureEnvelope{KeyID: "unknown", Algorithm: TrustCoreAlgorithmDescriptor{AlgorithmID: "ML-DSA-65"}, SignatureBytes: make([]byte, 3309)})
	if err != nil {
		t.Fatal(err)
	}
	result := queue.Receive("agent:recipient", message.MessageID)
	if result.Accepted || result.Reason != "unsupported_signature" {
		t.Fatal("queue accepted fabricated signature")
	}
}
