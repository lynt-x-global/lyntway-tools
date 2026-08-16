package receipt

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// A key attestation is how one deployment can sign each customer's receipts
// with that customer's own key, without anyone needing a directory of keys
// to check them.
//
// # Why per-customer keys at all
//
// A single deployment key signs every customer's receipts identically. Two
// things follow, and both matter commercially. A customer cannot show that
// a receipt is theirs rather than another customer's — the signature says
// only "this service issued it". And a compromise of that one key forges
// receipts for everybody at once, so the blast radius is the whole book of
// business.
//
// # Why not simply publish every key
//
// The obvious approach is to add each customer's public key to the
// published key set. That set is public, so it would disclose how many
// customers exist and, if the identifiers were meaningful, who they are.
// The transparency log already withholds receipts for exactly this reason:
// operational metadata about customers is theirs, not ours to publish.
//
// # What an attestation does instead
//
// The deployment key signs a short statement: this key identifier, this
// public key, this algorithm, may sign for this scope. The statement
// travels inside the receipt.
//
// A verifier then needs one long-lived public key — the deployment's — to
// check any customer's receipt. They check the statement was signed by the
// deployment, then check the receipt was signed by the key the statement
// names. Offline verification survives intact, no directory is consulted,
// and no customer learns of another's existence.
//
// This is the same shape as a certificate, deliberately: it is a solved
// problem, and inventing a different one here would be a poor use of the
// novelty budget.

// KeyAttestationVersion identifies the attestation schema.
const KeyAttestationVersion = "lyntway-key-attestation/1"

// keyAttestationDomain separates attestation signatures from receipt
// signatures made by the same key.
//
// Without a domain separator, a signature over one structure could be
// presented as a signature over another that happened to canonicalise
// identically. The two never can here, but relying on that is relying on an
// accident of the schemas rather than on a stated rule.
const keyAttestationDomain = "lyntway-key-attestation-v1\x00"

// KeyAttestation is a signed statement that a key may issue receipts for a
// scope.
type KeyAttestation struct {
	// Version is the attestation schema version.
	Version string `json:"version"`

	// KeyID identifies the attested key. It is opaque on purpose: a
	// verifier needs it only to match the receipt's signature, and a
	// meaningful identifier would name the customer to anyone holding a
	// receipt or reading a published key set.
	KeyID string `json:"key_id"`

	// Algorithm is the scheme the attested key signs with.
	Algorithm Algorithm `json:"algorithm"`

	// PublicKey is the attested key, base64 standard encoding of its raw
	// form — 32 bytes for Ed25519, an uncompressed point for ES256.
	PublicKey string `json:"public_key"`

	// Scope is the chain prefix this key may sign for.
	//
	// This is what stops one customer's key from signing receipts that
	// appear to belong to another. Without it an attestation would say only
	// "this key is legitimate", and a customer could issue receipts against
	// any chain they cared to name.
	//
	// Expressed as a prefix rather than an identifier so that this package
	// need not know how chains are named. Whoever mints attestations
	// decides the convention.
	Scope string `json:"scope"`

	// NotBefore and NotAfter bound the attestation's validity, RFC 3339
	// UTC. Optional; an attestation without them does not expire.
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`

	// RootKeyID identifies the key that signed this attestation. A verifier
	// resolves it from the deployment's published keys.
	RootKeyID string `json:"root_key_id"`

	// RootAlgorithm is the scheme the root key signed with.
	RootAlgorithm Algorithm `json:"root_algorithm"`

	// Signature is the root key's signature over this attestation, base64.
	//
	// omitempty is load-bearing, not tidiness. The signing input is this
	// structure with the signature cleared, so without it the covered bytes
	// would contain "signature":"" — a field that other implementations
	// omit when they drop the key. Every signature would then verify in Go
	// and fail everywhere else, which reads as tampering rather than as a
	// disagreement about an empty string.
	Signature string `json:"signature,omitempty"`
}

// signingInput returns the exact bytes an attestation's signature covers.
//
// The signature field is excluded, since it cannot cover itself. Everything
// else is included: dropping any field from the covered bytes would let it
// be changed after signing, and each one here is load-bearing.
func (a *KeyAttestation) signingInput() ([]byte, error) {
	unsigned := *a
	unsigned.Signature = ""

	body, err := Canonicalize(&unsigned)
	if err != nil {
		return nil, fmt.Errorf("receipt: canonicalizing key attestation: %w", err)
	}
	return append([]byte(keyAttestationDomain), body...), nil
}

// AttestKey signs a statement that a key may issue receipts for a scope.
//
// The root signer is the deployment's own key — the one published at a
// well-known location and already trusted by verifiers.
func AttestKey(root Signer, keyID string, alg Algorithm, publicKey []byte, scope string) (*KeyAttestation, error) {
	switch {
	case root == nil:
		return nil, errors.New("receipt: a root signer is required to attest a key")
	case strings.TrimSpace(keyID) == "":
		return nil, errors.New("receipt: an attested key needs a key ID")
	case len(publicKey) == 0:
		return nil, errors.New("receipt: an attested key needs a public key")
	case strings.TrimSpace(scope) == "":
		// An unscoped attestation would authorise a key to sign for every
		// chain, which is the whole property this exists to prevent. There
		// is no legitimate use for one, so it is refused rather than
		// documented as dangerous.
		return nil, errors.New("receipt: an attested key needs a scope; an unscoped key could sign for any chain")
	}
	if _, ok := algorithms[alg]; !ok {
		return nil, fmt.Errorf("receipt: unsupported algorithm %q", alg)
	}

	a := &KeyAttestation{
		Version:       KeyAttestationVersion,
		KeyID:         keyID,
		Algorithm:     alg,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
		Scope:         scope,
		RootKeyID:     root.KeyID(),
		RootAlgorithm: root.Algorithm(),
	}

	input, err := a.signingInput()
	if err != nil {
		return nil, err
	}
	sig, err := root.Sign(input)
	if err != nil {
		return nil, fmt.Errorf("receipt: signing key attestation: %w", err)
	}
	a.Signature = base64.StdEncoding.EncodeToString(sig)

	return a, nil
}

// Errors returned when an attestation cannot be trusted.
var (
	// ErrAttestationInvalid means the attestation's own signature does not
	// check out, so nothing it says can be relied on.
	ErrAttestationInvalid = errors.New("receipt: key attestation is not valid")

	// ErrAttestationScope means the attested key is not authorised for the
	// chain the receipt claims.
	ErrAttestationScope = errors.New("receipt: key is not attested for this chain")
)

// Verify checks the attestation against the deployment's published keys and
// returns the attested public key.
//
// The returned key must not be used unless this returns nil. An attestation
// carries its own public key, so a verifier that skipped this check would
// accept a receipt signed by whoever wrote the attestation — which is to
// say, anybody.
func (a *KeyAttestation) Verify(roots KeyResolver, now time.Time) (crypto.PublicKey, error) {
	if a == nil {
		return nil, errors.New("receipt: nil key attestation")
	}
	if roots == nil {
		return nil, errors.New("receipt: nil key resolver")
	}
	if a.Version != KeyAttestationVersion {
		return nil, fmt.Errorf("%w: unsupported version %q", ErrAttestationInvalid, a.Version)
	}
	if a.Scope == "" {
		return nil, fmt.Errorf("%w: no scope", ErrAttestationInvalid)
	}

	rootKey, err := roots.ResolveKey(a.RootKeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestationInvalid, err)
	}

	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not valid base64", ErrAttestationInvalid)
	}
	input, err := a.signingInput()
	if err != nil {
		return nil, err
	}
	if !VerifyRaw(a.RootAlgorithm, rootKey, input, sig) {
		return nil, fmt.Errorf("%w: the deployment key did not sign this statement", ErrAttestationInvalid)
	}

	// Validity is checked only after the signature, because before that the
	// dates are just numbers an attacker chose.
	if err := a.checkValidity(now); err != nil {
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not valid base64", ErrAttestationInvalid)
	}
	pub, err := ParsePublicKey(a.Algorithm, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestationInvalid, err)
	}
	return pub, nil
}

func (a *KeyAttestation) checkValidity(now time.Time) error {
	if a.NotBefore != "" {
		t, err := time.Parse(time.RFC3339, a.NotBefore)
		if err != nil {
			return fmt.Errorf("%w: not_before is not RFC 3339", ErrAttestationInvalid)
		}
		if now.Before(t) {
			return fmt.Errorf("%w: not valid until %s", ErrAttestationInvalid, a.NotBefore)
		}
	}
	if a.NotAfter != "" {
		t, err := time.Parse(time.RFC3339, a.NotAfter)
		if err != nil {
			return fmt.Errorf("%w: not_after is not RFC 3339", ErrAttestationInvalid)
		}
		if now.After(t) {
			return fmt.Errorf("%w: expired at %s", ErrAttestationInvalid, a.NotAfter)
		}
	}
	return nil
}

// CoversChain reports whether the attested key may sign for a chain.
func (a *KeyAttestation) CoversChain(chainID string) bool {
	return a != nil && a.Scope != "" && strings.HasPrefix(chainID, a.Scope)
}
