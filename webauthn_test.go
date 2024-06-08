package webauthn

import (
	"encoding/base64"
	"testing"
)

func TestParseAndVerifyAttestation(t *testing.T) {
	attResp := AuthenticatorAttestationResponse{
		ClientDataJSON:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
		AttestationObject: base64.StdEncoding.EncodeToString([]byte("attestationObject")),
	}

	parsedData, err := ParseAttestationResponse(attResp)
	if err != nil {
		t.Fatalf("failed to parse attestation response: %v", err)
	}

	err = VerifyAttestation(parsedData, attResp.ClientDataJSON)
	if err != nil {
		t.Fatalf("failed to verify attestation: %v", err)
	}
}

func TestParseAndVerifyAssertion(t *testing.T) {
	assertResp := AuthenticatorAssertionResponse{
		ClientDataJSON:    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
		AuthenticatorData: base64.StdEncoding.EncodeToString([]byte("authenticatorData")),
		Signature:         base64.StdEncoding.EncodeToString([]byte("signature")),
	}

	parsedData, err := ParseAssertionResponse(assertResp)
	if err != nil {
		t.Fatalf("failed to parse assertion response: %v", err)
	}

	err = VerifyAssertion(parsedData, assertResp.ClientDataJSON, assertResp.Signature)
	if err != nil {
		t.Fatalf("failed to verify assertion: %v", err)
	}
}
