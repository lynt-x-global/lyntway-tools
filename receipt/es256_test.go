package receipt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

func testES256(t *testing.T) (*ES256Signer, StaticKeyResolver) {
	t.Helper()
	s, err := GenerateES256Signer("kv-es256-1")
	if err != nil {
		t.Fatalf("generating ES256 signer: %v", err)
	}
	return s, StaticKeyResolver{s.KeyID(): s.Public()}
}

func TestES256RoundTrip(t *testing.T) {
	signer, keys := testES256(t)
	r := validReceipt()
	r.Issuer.KeyID = signer.KeyID()
	mustSign(t, r, signer)

	if r.Signature.Algorithm != AlgES256 {
		t.Fatalf("algorithm = %q, want %q", r.Signature.Algorithm, AlgES256)
	}

	res, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Algorithm != AlgES256 {
		t.Errorf("result algorithm = %q, want %q", res.Algorithm, AlgES256)
	}
}

// TestES256SignatureIsFixedWidth pins the wire format. ASN.1 DER is Go's
// default output and is variable-length, so a signer that forgot to convert
// would still verify locally while being unreadable to any JOSE or COSE
// implementation.
func TestES256SignatureIsFixedWidth(t *testing.T) {
	signer, _ := testES256(t)
	// Many signatures, because DER length varies with leading zero bytes
	// and a single sample can easily miss the short cases.
	for i := 0; i < 200; i++ {
		sig, err := signer.Sign([]byte("payload"))
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		if len(sig) != es256SignatureSize {
			t.Fatalf("signature is %d bytes, want %d (DER leaking through?)",
				len(sig), es256SignatureSize)
		}
	}
}

// TestES256ShortComponentPadding is the regression test for the failure
// mode that would otherwise appear roughly once in 256 signatures: a field
// element with a leading zero byte serialising short, shifting S into R's
// tail.
func TestES256ShortComponentPadding(t *testing.T) {
	// r has a leading zero byte when written big-endian; s is full width.
	r := new(big.Int).SetBytes(append([]byte{0x00, 0x7f}, make([]byte, 30)...))
	s := new(big.Int).SetBytes(func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = 0xAB
		}
		return b
	}())

	sig, err := encodeES256Signature(r, s)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if len(sig) != es256SignatureSize {
		t.Fatalf("length = %d, want %d", len(sig), es256SignatureSize)
	}

	gotR, gotS, err := DecodeES256Signature(sig)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if gotR.Cmp(r) != 0 {
		t.Errorf("r round trip failed:\n got %x\nwant %x", gotR.Bytes(), r.Bytes())
	}
	if gotS.Cmp(s) != 0 {
		t.Errorf("s round trip failed:\n got %x\nwant %x", gotS.Bytes(), s.Bytes())
	}
}

func TestES256TamperDetection(t *testing.T) {
	signer, keys := testES256(t)
	r := validReceipt()
	r.Issuer.KeyID = signer.KeyID()
	mustSign(t, r, signer)

	r.Governance.Decision = DecisionAllow

	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); err == nil {
		t.Fatal("tampered ES256 receipt verified")
	}
}

func TestES256SignatureTamper(t *testing.T) {
	signer, keys := testES256(t)
	r := validReceipt()
	r.Issuer.KeyID = signer.KeyID()
	mustSign(t, r, signer)

	raw, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	raw[10] ^= 0xFF
	r.Signature.Value = base64.StdEncoding.EncodeToString(raw)

	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

// TestCrossAlgorithmKeyConfusion proves an Ed25519 key cannot be used to
// verify a receipt that declares ES256, or vice versa. Without the key-type
// check in Verify, a mismatched pair would reach the verification function
// and its behaviour would be an implementation detail rather than a
// refusal.
func TestCrossAlgorithmKeyConfusion(t *testing.T) {
	ed, _ := testSigner(t)
	ec, _ := testES256(t)

	t.Run("es256 receipt with an ed25519 key", func(t *testing.T) {
		r := validReceipt()
		r.Issuer.KeyID = ec.KeyID()
		mustSign(t, r, ec)

		keys := StaticKeyResolver{ec.KeyID(): ed.Public()}
		if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})

	t.Run("ed25519 receipt with an es256 key", func(t *testing.T) {
		r := validReceipt()
		r.Issuer.KeyID = ed.KeyID()
		mustSign(t, r, ed)

		keys := StaticKeyResolver{ed.KeyID(): ec.Public()}
		if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

// TestWrongCurveRejected proves a P-384 key is refused rather than being
// coerced into an ES256 verification.
func TestWrongCurveRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating P-384 key: %v", err)
	}
	if _, err := NewES256Signer("bad-curve", priv); err == nil {
		t.Fatal("expected a P-384 key to be refused for ES256")
	}

	signer, _ := testES256(t)
	r := validReceipt()
	r.Issuer.KeyID = signer.KeyID()
	mustSign(t, r, signer)

	keys := StaticKeyResolver{signer.KeyID(): &priv.PublicKey}
	if _, err := Verify(r, keys, VerifyOptions{Now: r.mustIssuedAt(t)}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestBothAlgorithmsChainTogether proves a chain survives a key rotation
// that also changes algorithm — the migration path from an in-process
// Ed25519 key to a non-exportable Key Vault P-256 key.
func TestBothAlgorithmsChainTogether(t *testing.T) {
	ed, _ := testSigner(t)
	ec, _ := testES256(t)

	keys := StaticKeyResolver{
		ed.KeyID(): ed.Public(),
		ec.KeyID(): ec.Public(),
	}

	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)

	b, err := NewChainBuilder("ws_migrating", ed)
	if err != nil {
		t.Fatalf("chain builder: %v", err)
	}
	var chain []*Receipt
	for i := 0; i < 2; i++ {
		r := validReceipt()
		r.ID = "rcpt_ed_" + itoa(i)
		r.IssuedAt = FormatTime(base.Add(time.Duration(i) * time.Second))
		r.Issuer.KeyID = ed.KeyID()
		if err := b.Issue(r); err != nil {
			t.Fatalf("issuing: %v", err)
		}
		chain = append(chain, r)
	}

	// Rotate to the Key Vault-backed key mid-chain.
	head, err := Digest(chain[len(chain)-1])
	if err != nil {
		t.Fatalf("digesting head: %v", err)
	}
	b2, err := ResumeChainBuilder("ws_migrating", ec, uint64(len(chain)), head)
	if err != nil {
		t.Fatalf("resuming under the new key: %v", err)
	}
	for i := 0; i < 2; i++ {
		r := validReceipt()
		r.ID = "rcpt_ec_" + itoa(i)
		r.IssuedAt = FormatTime(base.Add(time.Duration(len(chain)+i) * time.Second))
		r.Issuer.KeyID = ec.KeyID()
		if err := b2.Issue(r); err != nil {
			t.Fatalf("issuing after rotation: %v", err)
		}
		chain = append(chain, r)
	}

	res, err := VerifyChain(chain, keys, VerifyOptions{Now: base.Add(time.Hour)})
	if err != nil {
		t.Fatalf("a chain spanning a key and algorithm rotation must verify: %v", err)
	}
	if res.Length != 4 {
		t.Errorf("length = %d, want 4", res.Length)
	}
}

func TestES256RegisteredInAlgorithmList(t *testing.T) {
	var found bool
	for _, a := range SupportedAlgorithms() {
		if a == AlgES256 {
			found = true
		}
	}
	if !found {
		t.Errorf("es256 missing from SupportedAlgorithms: %v", SupportedAlgorithms())
	}
}
