package receipt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Algorithm names a signature scheme.
//
// The algorithm travels inside the receipt so that adding a scheme later is
// a registry entry rather than a schema break. Post-quantum migration is the
// motivating case: when ML-DSA is added, receipts signed under Ed25519
// remain verifiable unchanged, and a verifier's policy decides which
// algorithms it still accepts.
type Algorithm string

const (
	// AlgEd25519 is EdDSA over Curve25519 (RFC 8032). The default: small
	// keys, small signatures, no parameter choices to get wrong, and a
	// stdlib implementation with no external supply chain.
	AlgEd25519 Algorithm = "ed25519"
)

// algorithmInfo describes a registered signature scheme.
type algorithmInfo struct {
	// verify checks sig over input using pub, returning false on any
	// mismatch including a wrong key type.
	verify func(pub crypto.PublicKey, input, sig []byte) bool
	// publicKeyOK reports whether pub is the right key type for this
	// algorithm. Checked before verification to prevent a caller from
	// pairing a key of one type with an algorithm identifier of another.
	publicKeyOK func(pub crypto.PublicKey) bool
	// parsePublic turns a raw encoded public key into one this scheme can
	// verify with. Part of the registry entry so that supporting a new
	// algorithm stays a single addition rather than an edit in three
	// places, one of which somebody will forget.
	parsePublic func(raw []byte) (crypto.PublicKey, error)
	// marshalPublic is the inverse of parsePublic. Kept alongside it so the
	// two cannot drift into disagreeing about the encoding, which would
	// fail as an invalid signature and send the reader looking at the
	// wrong thing entirely.
	marshalPublic func(pub crypto.PublicKey) ([]byte, error)
}

// algorithms is the registry of supported schemes. Adding an entry is the
// entire cost of supporting a new algorithm on the verification path.
var algorithms = map[Algorithm]algorithmInfo{
	AlgEd25519: {
		verify: func(pub crypto.PublicKey, input, sig []byte) bool {
			k, ok := pub.(ed25519.PublicKey)
			if !ok || len(k) != ed25519.PublicKeySize {
				return false
			}
			// ed25519.Verify is constant time with respect to the
			// signature and does not panic on malformed input of the
			// correct length.
			if len(sig) != ed25519.SignatureSize {
				return false
			}
			return ed25519.Verify(k, input, sig)
		},
		publicKeyOK: func(pub crypto.PublicKey) bool {
			k, ok := pub.(ed25519.PublicKey)
			return ok && len(k) == ed25519.PublicKeySize
		},
		parsePublic: func(raw []byte) (crypto.PublicKey, error) {
			if len(raw) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("receipt: ed25519 public key must be %d bytes, got %d",
					ed25519.PublicKeySize, len(raw))
			}
			return ed25519.PublicKey(append([]byte(nil), raw...)), nil
		},
		marshalPublic: func(pub crypto.PublicKey) ([]byte, error) {
			k, ok := pub.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("receipt: %T is not an ed25519 public key", pub)
			}
			return append([]byte(nil), k...), nil
		},
	},
}

// MarshalPublicKey encodes a public key in the raw form receipts and
// attestations carry.
func MarshalPublicKey(alg Algorithm, pub crypto.PublicKey) ([]byte, error) {
	info, ok := algorithms[alg]
	if !ok {
		return nil, fmt.Errorf("receipt: unsupported algorithm %q", alg)
	}
	if info.marshalPublic == nil {
		return nil, fmt.Errorf("receipt: algorithm %q cannot marshal a public key", alg)
	}
	return info.marshalPublic(pub)
}

// RawPublicKey returns a signer's public key in raw encoded form.
//
// A deployment publishing its keys and a deployment attesting a customer's
// key need the same bytes, so both take them from here rather than each
// encoding a key from the type switch outward.
func RawPublicKey(s Signer) ([]byte, error) {
	if s == nil {
		return nil, errors.New("receipt: nil signer")
	}
	return MarshalPublicKey(s.Algorithm(), s.Public())
}

// ParsePublicKey turns a raw encoded public key into one this package can
// verify with.
//
// Raw rather than DER because that is the form receipts and attestations
// carry: an Ed25519 key is 32 bytes and an ES256 key an uncompressed point,
// and wrapping either in ASN.1 to unwrap it again would add a parser to the
// trust path for no benefit.
func ParsePublicKey(alg Algorithm, raw []byte) (crypto.PublicKey, error) {
	info, ok := algorithms[alg]
	if !ok {
		return nil, fmt.Errorf("receipt: unsupported algorithm %q", alg)
	}
	if info.parsePublic == nil {
		return nil, fmt.Errorf("receipt: algorithm %q cannot parse a raw public key", alg)
	}
	return info.parsePublic(raw)
}

// SupportedAlgorithms returns the algorithms this build can verify.
func SupportedAlgorithms() []Algorithm {
	out := make([]Algorithm, 0, len(algorithms))
	for a := range algorithms {
		out = append(out, a)
	}
	return out
}

// Signer produces signatures over a receipt's signing input.
//
// It is an interface rather than a concrete key so that the private key
// never has to exist in this process. A production deployment implements
// Signer against Azure Key Vault or an HSM, where Sign is a remote call and
// the key material is non-exportable; the local implementation below exists
// for development, tests, and air-gapped builds.
//
// Implementations must be safe for concurrent use: the gateway signs from
// every request goroutine.
type Signer interface {
	// KeyID returns the stable identifier of the signing key. Rotation
	// means a new KeyID, never a new key under an existing one — otherwise
	// a verifier holding the old public key would report a valid receipt
	// as forged.
	KeyID() string

	// Algorithm returns the scheme this signer produces.
	Algorithm() Algorithm

	// Sign returns a signature over input.
	Sign(input []byte) ([]byte, error)

	// Public returns the public key corresponding to the signing key, so a
	// deployment can publish its own JWKS without a second source of truth.
	Public() crypto.PublicKey
}

// Ed25519Signer signs receipts with an in-process Ed25519 private key.
//
// Suitable for development, tests, on-device deployments, and air-gapped
// installations. For hosted production, prefer a Signer backed by a key
// management service so the private key is never resident in application
// memory.
type Ed25519Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewEd25519Signer wraps an existing private key.
//
// keyID must be stable for the life of the key and unique across every key
// the deployment has ever used.
func NewEd25519Signer(keyID string, priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if keyID == "" {
		return nil, errors.New("receipt: key ID must not be empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("receipt: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	// An Ed25519 private key is a seed followed by the public key derived
	// from it, and nothing about the encoding forces the two halves to
	// agree. Sixty-four random bytes satisfy every length check here and
	// are what `openssl rand -base64 64` produces, so it is the obvious
	// thing for an operator to paste into the signing key variable.
	//
	// Such a key signs with the seed and publishes the other half, so the
	// deployment starts clean, serves a key file, issues receipts all
	// week, and every one of them fails verification — not as a signature
	// that is wrong, but as a signature by a key nobody can establish. The
	// failure appears only in front of whoever the evidence was produced
	// for, which is the one audience it must never fail in front of.
	//
	// Refused here rather than in the server so the CLI, the device agent
	// and anything embedding this package are covered by the same check,
	// and for the reason loadES256Signer already refuses a bare scalar: a
	// key for the wrong curve is indistinguishable from a valid one until
	// signatures start failing.
	// Derived from the seed rather than read back through priv.Public(),
	// which copies the stored half and would therefore compare it with
	// itself. Sign uses the seed, so the seed is what the comparison has
	// to start from.
	derived := ed25519.NewKeyFromSeed(priv.Seed())
	if !ed25519.PublicKey(derived[ed25519.SeedSize:]).Equal(ed25519.PublicKey(priv[ed25519.SeedSize:])) {
		return nil, errors.New("receipt: this private key's two halves disagree — " +
			"the public key it carries is not the one its seed derives, so every receipt it signs " +
			"would be published under a key that cannot verify it. An Ed25519 private key is a " +
			"32-byte seed followed by its own public key, not 64 random bytes; pass the 32-byte seed instead")
	}
	return &Ed25519Signer{keyID: keyID, priv: priv}, nil
}

// GenerateEd25519Signer creates a fresh key pair.
//
// Intended for tests and local development. Production keys should be
// generated inside a key management service and never leave it.
func GenerateEd25519Signer(keyID string) (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("receipt: generating key: %w", err)
	}
	_ = pub
	return NewEd25519Signer(keyID, priv)
}

// KeyID implements Signer.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// Algorithm implements Signer.
func (s *Ed25519Signer) Algorithm() Algorithm { return AlgEd25519 }

// Sign implements Signer.
func (s *Ed25519Signer) Sign(input []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, input), nil
}

// Public implements Signer.
func (s *Ed25519Signer) Public() crypto.PublicKey {
	return s.priv.Public()
}

// VerifyRaw checks a signature over arbitrary bytes under a registered
// algorithm.
//
// Exported so that other signed artefacts in this module — transparency log
// tree heads, for instance — can reuse the same algorithm registry rather
// than each growing its own switch on key types. A second hand-rolled
// verification path is a second place for an algorithm-confusion bug to
// live.
//
// Returns false for an unregistered algorithm or a key of the wrong type
// for it, so a caller cannot be talked into accepting a signature the
// registry does not actually support.
func VerifyRaw(alg Algorithm, pub crypto.PublicKey, message, signature []byte) bool {
	info, ok := algorithms[alg]
	if !ok {
		return false
	}
	if !info.publicKeyOK(pub) {
		return false
	}
	return info.verify(pub, message, signature)
}

// Sign validates r, computes its signing input, and attaches a signature.
//
// Validation runs first and unconditionally. Signing an invalid receipt
// would produce a cryptographically sound attestation of a structurally
// meaningless claim — for instance a receipt asserting full-strength
// governance while reporting an unavailable detector. The signature would
// verify, and the receipt would still be a lie. Refusing to sign is the only
// place this can be caught before it reaches a third party.
//
// Sign sets r.Version and r.Issuer.KeyID if they are unset, then mutates r
// in place to attach the signature.
func Sign(r *Receipt, signer Signer) error {
	if signer == nil {
		return errors.New("receipt: signer must not be nil")
	}

	if r.Version == "" {
		r.Version = SchemaVersion
	}
	if r.Issuer.KeyID == "" {
		r.Issuer.KeyID = signer.KeyID()
	}
	if r.Issuer.KeyID != signer.KeyID() {
		return fmt.Errorf("receipt: issuer key_id %q does not match signer key_id %q",
			r.Issuer.KeyID, signer.KeyID())
	}

	alg := signer.Algorithm()
	if _, ok := algorithms[alg]; !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if err := r.Validate(); err != nil {
		return err
	}

	// Clear any existing signature before computing the input, so re-signing
	// a receipt produces the same bytes as signing it the first time.
	r.Signature = nil

	input, err := SigningInput(r)
	if err != nil {
		return err
	}

	sig, err := signer.Sign(input)
	if err != nil {
		return fmt.Errorf("receipt: signing: %w", err)
	}

	r.Signature = &Signature{
		Algorithm:        alg,
		KeyID:            signer.KeyID(),
		Canonicalization: CanonicalizationJCS,
		Value:            base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}
