package receipt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// ES256 exists because Azure Key Vault cannot hold an Ed25519 key.
//
// Key Vault supports RSA and EC over P-256, P-256K, P-384 and P-521 — there
// is no Ed25519 option, and the same is true of most cloud key management
// services. That leaves a genuine conflict:
//
//   - Ed25519 is the interop default for signed action receipts. Every other
//     implementation in the ecosystem uses it, so choosing a different
//     algorithm as the only option would produce receipts nothing else can
//     verify.
//   - Regulated customers require non-exportable, HSM-backed key custody,
//     which for Ed25519 no major KMS can provide.
//
// Supporting both resolves it rather than compromising on either. Ed25519
// remains the default for interoperability; ES256 is offered where key
// custody outranks portability, and a non-exportable P-256 key in Key Vault
// signs without the private key ever entering this process.
//
// This is exactly the situation the algorithm registry was built for: a
// deployment choice, carried inside each receipt, with no schema change.

// AlgES256 is ECDSA over P-256 with SHA-256, as defined by RFC 7518.
//
// Signatures are the fixed-width 64-byte R‖S form used by JOSE and COSE,
// not ASN.1 DER. DER is Go's default output and would be the easy choice,
// but it is variable-length and admits multiple encodings of the same
// signature — which means two implementations can disagree about whether
// bytes match. Fixed-width R‖S is what the surrounding ecosystem uses.
const AlgES256 Algorithm = "es256"

// es256SignatureSize is two 32-byte field elements, R followed by S.
const es256SignatureSize = 64

func init() {
	algorithms[AlgES256] = algorithmInfo{
		verify: func(pub crypto.PublicKey, input, sig []byte) bool {
			k, ok := pub.(*ecdsa.PublicKey)
			if !ok || k.Curve != elliptic.P256() {
				return false
			}
			if len(sig) != es256SignatureSize {
				return false
			}
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			digest := sha256.Sum256(input)
			return ecdsa.Verify(k, digest[:], r, s)
		},
		publicKeyOK: func(pub crypto.PublicKey) bool {
			k, ok := pub.(*ecdsa.PublicKey)
			return ok && k.Curve == elliptic.P256()
		},
		parsePublic: func(raw []byte) (crypto.PublicKey, error) {
			// UnmarshalCompressed and Unmarshal both reject points that are
			// not on the curve, which is the check that matters: an
			// off-curve point can leak the private key of whoever operates
			// on it.
			x, y := elliptic.Unmarshal(elliptic.P256(), raw)
			if x == nil {
				return nil, errors.New("receipt: not a valid uncompressed P-256 point")
			}
			return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
		},
		marshalPublic: func(pub crypto.PublicKey) ([]byte, error) {
			k, ok := pub.(*ecdsa.PublicKey)
			if !ok || k.Curve != elliptic.P256() {
				return nil, errors.New("receipt: not a P-256 public key")
			}
			return elliptic.Marshal(k.Curve, k.X, k.Y), nil
		},
	}
}

// ES256Signer signs receipts with an in-process ECDSA P-256 key.
//
// For hosted production, prefer a Signer backed by a key management service
// so the private key is never resident in application memory. This type
// exists for development, tests, and air-gapped builds — and as the
// reference for what a remote signer must produce.
type ES256Signer struct {
	keyID string
	priv  *ecdsa.PrivateKey
}

// NewES256Signer wraps an existing P-256 private key.
func NewES256Signer(keyID string, priv *ecdsa.PrivateKey) (*ES256Signer, error) {
	if keyID == "" {
		return nil, errors.New("receipt: key ID must not be empty")
	}
	if priv == nil {
		return nil, errors.New("receipt: private key must not be nil")
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("receipt: ES256 requires curve P-256, got %s", priv.Curve.Params().Name)
	}
	return &ES256Signer{keyID: keyID, priv: priv}, nil
}

// GenerateES256Signer creates a fresh P-256 key pair.
//
// Intended for tests and local development. Production keys should be
// generated inside a key management service and never leave it.
func GenerateES256Signer(keyID string) (*ES256Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("receipt: generating P-256 key: %w", err)
	}
	return NewES256Signer(keyID, priv)
}

// KeyID implements Signer.
func (s *ES256Signer) KeyID() string { return s.keyID }

// Algorithm implements Signer.
func (s *ES256Signer) Algorithm() Algorithm { return AlgES256 }

// Public implements Signer.
func (s *ES256Signer) Public() crypto.PublicKey { return &s.priv.PublicKey }

// Sign implements Signer, returning a fixed-width R‖S signature.
func (s *ES256Signer) Sign(input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("receipt: ES256 signing: %w", err)
	}
	return encodeES256Signature(r, sv)
}

// encodeES256Signature packs r and s into fixed 32-byte big-endian halves.
//
// Left-padding matters: a field element with leading zero bytes would
// otherwise serialise short, shifting S into R's tail and producing a
// signature that fails verification roughly one time in 256. That is the
// kind of defect that passes a hundred tests and then fails in production.
func encodeES256Signature(r, s *big.Int) ([]byte, error) {
	rb, sb := r.Bytes(), s.Bytes()
	if len(rb) > 32 || len(sb) > 32 {
		return nil, errors.New("receipt: ES256 signature component exceeds 32 bytes")
	}
	out := make([]byte, es256SignatureSize)
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out, nil
}

// DecodeES256Signature splits a fixed-width R‖S signature into its
// components.
//
// Exported so that a signer backed by a key management service returning a
// different encoding can convert into the form this package expects, and so
// tests can inspect signatures without reimplementing the layout.
func DecodeES256Signature(sig []byte) (r, s *big.Int, err error) {
	if len(sig) != es256SignatureSize {
		return nil, nil, fmt.Errorf("receipt: ES256 signature must be %d bytes, got %d",
			es256SignatureSize, len(sig))
	}
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]), nil
}
