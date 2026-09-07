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
	if _, err := readProtected(protected); err == nil {
		t.Fatal("headers naming no algorithm were accepted")
	}
}

// RFC 9943 reads the issuer and subject from the protected header before it
// opens the payload. Both must be there, and both must be what the payload
// says.
func TestAReceiptCarriesCWTClaimsThatMatchItsPayload(t *testing.T) {
	signer, _ := receipt.GenerateEd25519Signer("k1")
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
	r := testReceipt(t, signer)

	encoded, err := EncodeReceipt(r, signer)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify1(encoded, keys)
	if err != nil {
		t.Fatal(err)
	}
	if res.Claims == nil {
		t.Fatal("the envelope carries no CWT claims")
	}
	if res.Claims.Issuer != r.Issuer.KeyID || res.Claims.Subject != r.ID {
		t.Errorf("claims are iss=%q sub=%q, want iss=%q sub=%q",
			res.Claims.Issuer, res.Claims.Subject, r.Issuer.KeyID, r.ID)
	}
	// The claims are in the protected header, so they are under the
	// signature: label 15 must appear inside the first byte string.
	protected := Encode(Map{
		{Key: Uint(labelAlg), Value: Int(algEdDSA)},
		{Key: Uint(labelContentType), Value: Uint(contentTypeJSON)},
		{Key: Uint(labelKeyID), Value: Bytes(signer.KeyID())},
		{Key: Uint(labelCWTClaims), Value: Map{
			{Key: Uint(claimIssuer), Value: Text(r.Issuer.KeyID)},
			{Key: Uint(claimSubject), Value: Text(r.ID)},
		}},
	})
	if !bytes.Contains(encoded, protected) {
		t.Error("the protected header is not alg, content type, kid and CWT claims in that encoding")
	}
}

// An envelope whose claims disagree with its payload is two statements
// under one signature. Both are signed by the issuer's key, so only the
// comparison catches it.
func TestClaimsThatDisagreeWithThePayloadAreRefused(t *testing.T) {
	signer, _ := receipt.GenerateEd25519Signer("k1")
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
	r := testReceipt(t, signer)
	payload, _ := receipt.Canonicalize(r)

	for _, tc := range []struct {
		name   string
		claims Claims
	}{
		{"wrong subject", Claims{Issuer: r.Issuer.KeyID, Subject: "rcpt_somebody_else"}},
		{"wrong issuer", Claims{Issuer: "another-issuer", Subject: r.ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := Sign1With(signer, payload, Sign1Options{
				ContentType: Uint(contentTypeJSON), Claims: &tc.claims,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeReceipt(encoded, keys); err == nil {
				t.Fatal("a receipt whose claims disagree with its payload was accepted")
			}
		})
	}

	// A claims set with only one of the two is not conformant and is not
	// silently accepted as if it were absent.
	half := Encode(Map{
		{Key: Uint(labelAlg), Value: Int(algEdDSA)},
		{Key: Uint(labelKeyID), Value: Bytes("k1")},
		{Key: Uint(labelCWTClaims), Value: Map{{Key: Uint(claimIssuer), Value: Text("k1")}}},
	})
	if _, err := readProtected(half); err == nil {
		t.Error("a claims set naming no subject was accepted")
	}
}

// Receipts issued before the envelope carried claims are still receipts.
// Sign1 produces exactly that envelope, and DecodeReceipt must take it.
func TestAReceiptWithoutClaimsStillVerifies(t *testing.T) {
	signer, _ := receipt.GenerateEd25519Signer("k1")
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
	r := testReceipt(t, signer)
	payload, _ := receipt.Canonicalize(r)

	old, err := Sign1(signer, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, Encode(Uint(labelCWTClaims))[:1]) && bytes.Contains(old, []byte{0x0f, 0xa2}) {
		t.Fatal("the legacy envelope carries claims; this test no longer tests what it says")
	}
	decoded, err := DecodeReceipt(old, keys)
	if err != nil {
		t.Fatalf("a receipt without claims was refused: %v", err)
	}
	if decoded.ID != r.ID {
		t.Error("the wrong receipt came back")
	}
	res, _ := Verify1(old, keys)
	if res.Claims != nil {
		t.Error("claims were reported where none were carried")
	}
}

// A detached payload has to come from somewhere the verifier trusts, and
// Verify1 has nowhere to get it. It must say so rather than verify an
// empty payload.
func TestVerify1RefusesADetachedPayload(t *testing.T) {
	signer, _ := receipt.GenerateEd25519Signer("k1")
	keys := receipt.StaticKeyResolver{signer.KeyID(): signer.Public()}
	detached, err := Sign1With(signer, []byte("x"), Sign1Options{Detached: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify1(detached, keys); err == nil {
		t.Fatal("a detached payload was verified as if it were present")
	}
	// The structure carries null, encoded as 0xf6, where the payload was.
	if !bytes.Contains(detached, []byte{0xf6, 0x58, 0x40}) {
		t.Error("the detached structure does not carry null before the signature")
	}
}
