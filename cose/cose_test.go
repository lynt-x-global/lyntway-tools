package cose

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/lynt-x-global/lyntway-tools/receipt"
)

// The encoding must match RFC 8949 exactly, or a signature over it verifies
// nowhere but here. These are the examples from the specification.
func TestDeterministicEncoding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value Value
		want  string
	}{
		{"zero", Uint(0), "00"},
		{"just under the one-byte form", Uint(23), "17"},
		{"the one-byte form begins", Uint(24), "1818"},
		{"two-byte form", Uint(1000), "1903e8"},
		{"four-byte form", Uint(1000000), "1a000f4240"},
		{"minus one", Int(-1), "20"},
		{"the EdDSA identifier", Int(-8), "27"},
		{"the ES256 identifier", Int(-7), "26"},
		{"empty byte string", Bytes(nil), "40"},
		{"text", Text("a"), "6161"},
		{"empty map", Map{}, "a0"},
		{"array", Array{Uint(1), Uint(2)}, "820102"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hex.EncodeToString(Encode(tc.value)); got != tc.want {
				t.Errorf("encoded %s, want %s", got, tc.want)
			}
		})
	}
}

// Two encoders that order map keys differently produce different signing
// inputs, and every signature then fails in a way indistinguishable from
// tampering.
func TestMapKeysAreOrderedByTheirEncodedBytes(t *testing.T) {
	// Declared in an order no sensible sort would preserve.
	m := Map{
		{Key: Uint(4), Value: Text("kid")},
		{Key: Int(-7), Value: Text("alg")},
		{Key: Uint(1), Value: Text("one")},
		{Key: Uint(3), Value: Text("cty")},
	}
	first := Encode(m)

	// The same entries, declared differently, must encode identically.
	shuffled := Map{
		{Key: Uint(3), Value: Text("cty")},
		{Key: Uint(1), Value: Text("one")},
		{Key: Int(-7), Value: Text("alg")},
		{Key: Uint(4), Value: Text("kid")},
	}
	if !bytes.Equal(first, Encode(shuffled)) {
		t.Fatal("declaration order changed the encoding")
	}

	// Ordered by encoded key, so the positive labels come before the
	// negative one, which encodes as 0x26. Sorting by arithmetic value
	// would put -7 first and disagree with every other implementation.
	if first[1] != 0x01 {
		t.Errorf("first key is %#x, want the label 1", first[1])
	}
}

// A signature is a statement about bytes, so two byte sequences must not
// have one meaning.
func TestNonShortestEncodingsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"one-byte form for a value under 24", "1817"},
		{"two-byte form for a value under 256", "1900ff"},
		{"four-byte form for a value under 65536", "1a0000ffff"},
		{"eight-byte form for a small value", "1b00000000ffffffff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(tc.in)
			if _, _, _, err := decodeHead(raw); !errors.Is(err, ErrNotDeterministic) {
				t.Errorf("a non-shortest encoding was accepted: err = %v", err)
			}
		})
	}
}

func testReceipt(t *testing.T, signer receipt.Signer) *receipt.Receipt {
	t.Helper()
	r := &receipt.Receipt{
		Version:  receipt.SchemaVersion,
		ID:       "rcpt_cose_0001",
		IssuedAt: "2026-08-12T09:00:00Z",
		Issuer:   receipt.Issuer{KeyID: signer.KeyID(), Name: "Lyntway"},
		Chain:    receipt.Chain{ID: "ws_cose", Seq: 0},
		Action: receipt.Action{
			Surface: receipt.SurfacePrimitive, Direction: receipt.DirectionRequest,
			Method: "POST /v1/govern",
		},
		Actor: receipt.Actor{Type: receipt.ActorAgent, ID: "a", Source: receipt.IdentityNone},
		Content: receipt.Content{
			Algorithm:   receipt.DigestSHA256,
			InputDigest: receipt.DigestContent([]byte("hello")),
			Bytes:       5,
		},
		Governance: receipt.Governance{
			Mode: receipt.ModeFull, Decision: receipt.DecisionAllow,
			Detector: receipt.Detector{
				Engine: "lyntway-core", EngineVersion: "0.1.0",
				RulesetVersion: "core-2026.08.13", Health: receipt.HealthHealthy,
			},
			Policy: receipt.Policy{ID: "pack.core.default", Version: "v1"},
		},
	}
	r.Content.OutputDigest = r.Content.InputDigest
	if err := receipt.Sign(r, signer); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return r
}

func TestReceiptRoundTripThroughCOSE(t *testing.T) {
	signer, err := receipt.GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
	original := testReceipt(t, signer)

	encoded, err := EncodeReceipt(original, signer)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	decoded, err := DecodeReceipt(encoded, keys)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if decoded.ID != original.ID || decoded.Chain.ID != original.Chain.ID {
		t.Errorf("the receipt changed across the round trip")
	}

	// The content is byte-identical in both forms, which is the whole
	// reason for enveloping rather than remapping.
	a, _ := receipt.Canonicalize(original)
	b, _ := receipt.Canonicalize(decoded)
	if !bytes.Equal(a, b) {
		t.Error("the canonical bytes differ between the two forms")
	}
}

// Tampering anywhere the signature covers must break it.
func TestATamperedCOSEReceiptIsRefused(t *testing.T) {
	signer, err := receipt.GenerateEd25519Signer("k1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}

	encoded, err := EncodeReceipt(testReceipt(t, signer), signer)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	for _, offset := range []int{5, len(encoded) / 2, len(encoded) - 5} {
		tampered := append([]byte(nil), encoded...)
		tampered[offset] ^= 0x01
		if _, err := DecodeReceipt(tampered, keys); err == nil {
			t.Errorf("a receipt altered at byte %d still verified", offset)
		}
	}
}

// Trailing bytes mean two readers could disagree about where the structure
// ends, which is a signature covering an ambiguous thing.
func TestTrailingDataIsRefused(t *testing.T) {
	signer, _ := receipt.GenerateEd25519Signer("k1")
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}

	encoded, err := EncodeReceipt(testReceipt(t, signer), signer)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if _, err := DecodeReceipt(append(encoded, 0x00), keys); err == nil {
		t.Fatal("trailing data after the structure was accepted")
	}
}

// The COSE form is a second issuance, not a conversion. Somebody holding a
// receipt must not be able to present it as a COSE receipt from us.
func TestEncodingRequiresTheIssuersKey(t *testing.T) {
	issuer, _ := receipt.GenerateEd25519Signer("issuer-1")
	other, _ := receipt.GenerateEd25519Signer("somebody-else")
	r := testReceipt(t, issuer)

	if _, err := EncodeReceipt(r, other); err == nil {
		t.Fatal("a receipt was re-issued as COSE under a different key")
	}
	if _, err := EncodeReceipt(r, nil); err == nil {
		t.Fatal("a receipt was encoded as COSE with no key at all")
	}
}

// A second serialisation must not become a way to issue a receipt the
// schema would have refused.
func TestAnInvalidReceiptIsNotEncodable(t *testing.T) {
	signer, _ := receipt.GenerateEd25519Signer("k1")
	r := testReceipt(t, signer)
	// Blocked releases nothing, so an output digest describes content that
	// never existed.
	r.Governance.Decision = receipt.DecisionBlock

	if _, err := EncodeReceipt(r, signer); err == nil {
		t.Fatal("a receipt the schema refuses was encoded as COSE")
	}
}

// An envelope naming one key around a receipt naming another is a receipt
// whose issuer depends on which layer you read.
func TestEnvelopeAndReceiptMustNameTheSameKey(t *testing.T) {
	issuer, _ := receipt.GenerateEd25519Signer("issuer-1")
	r := testReceipt(t, issuer)

	// A valid envelope, signed by a key the verifier trusts, around a
	// receipt claiming a different issuer.
	other, _ := receipt.GenerateEd25519Signer("other-key")
	payload, _ := receipt.Canonicalize(r)
	encoded, err := Sign1(other, payload)
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}

	keys := receipt.StaticKeyResolver{other.KeyID(): other.Public()}
	if _, err := DecodeReceipt(encoded, keys); err == nil {
		t.Fatal("an envelope and receipt naming different keys were accepted")
	}
}

// Without a declared algorithm a verifier would have to guess, which is how
// algorithm confusion begins.
func TestProtectedHeadersMustNameAnAlgorithm(t *testing.T) {
	protected := Encode(Map{{Key: Uint(labelKeyID), Value: Bytes("k1")}})
	if _, _, err := readProtected(protected); err == nil {
		t.Fatal("headers naming no algorithm were accepted")
	}
}
