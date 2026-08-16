package receipt

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// KeyResolver maps a key ID to the public key that signed under it.
//
// Verification is offline by design: a resolver may be a static map baked
// into a binary, a pinned key on disk, a cached JWKS document, or a key
// distributed alongside a receipt bundle. Nothing in this package reaches
// the network, and nothing requires a Lyntway account.
type KeyResolver interface {
	// ResolveKey returns the public key for keyID, or ErrUnknownKey if it
	// is not known to this verifier.
	ResolveKey(keyID string) (crypto.PublicKey, error)
}

// StaticKeyResolver resolves keys from an in-memory map.
type StaticKeyResolver map[string]crypto.PublicKey

// ResolveKey implements KeyResolver.
func (s StaticKeyResolver) ResolveKey(keyID string) (crypto.PublicKey, error) {
	k, ok := s[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	return k, nil
}

// NewEd25519Resolver builds a resolver from raw 32-byte Ed25519 public keys.
func NewEd25519Resolver(keys map[string][]byte) (StaticKeyResolver, error) {
	out := make(StaticKeyResolver, len(keys))
	for id, raw := range keys {
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("receipt: public key %q must be %d bytes, got %d",
				id, ed25519.PublicKeySize, len(raw))
		}
		out[id] = ed25519.PublicKey(raw)
	}
	return out, nil
}

// VerifyOptions tunes what a verifier will accept.
//
// The zero value is a sensible strict default: every algorithm this build
// supports is accepted, receipts of any age are accepted, and degraded
// receipts verify successfully while being reported as degraded.
type VerifyOptions struct {
	// AcceptedAlgorithms restricts which signature schemes are accepted.
	// Nil means every algorithm this build supports.
	//
	// Set this when deprecating an algorithm: a verifier that no longer
	// trusts a scheme should reject it explicitly rather than continuing to
	// accept signatures it has decided are too weak.
	AcceptedAlgorithms []Algorithm

	// MaxAge rejects receipts issued longer ago than this. Zero means no
	// age limit.
	MaxAge time.Duration

	// MaxClockSkew tolerates receipts issued slightly in the future,
	// accommodating clock drift between issuer and verifier. Defaults to
	// five minutes when zero. A receipt issued further ahead than this is
	// rejected: a future timestamp is either a misconfigured clock or an
	// attempt to extend a receipt's apparent validity.
	MaxClockSkew time.Duration

	// RequireFullStrength rejects receipts whose governance was degraded or
	// bypassed.
	//
	// Off by default, and that default is deliberate. A degraded receipt is
	// honest evidence that partial governance ran, and discarding it would
	// leave a hole in the record exactly where scrutiny is most warranted.
	// Turn this on only when a specific control genuinely requires
	// full-strength governance, and expect to handle the rejections.
	RequireFullStrength bool

	// Now overrides the clock, for tests and for verifying against a
	// historical point in time. Zero means time.Now.
	Now time.Time
}

func (o *VerifyOptions) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

func (o *VerifyOptions) skew() time.Duration {
	if o.MaxClockSkew == 0 {
		return 5 * time.Minute
	}
	return o.MaxClockSkew
}

func (o *VerifyOptions) algorithmAccepted(a Algorithm) bool {
	if len(o.AcceptedAlgorithms) == 0 {
		_, ok := algorithms[a]
		return ok
	}
	for _, allowed := range o.AcceptedAlgorithms {
		if allowed == a {
			_, ok := algorithms[a]
			return ok
		}
	}
	return false
}

// Result describes the outcome of verifying a single receipt.
//
// Verification returns structure rather than a boolean because the useful
// answer is not binary. A receipt can be cryptographically perfect and still
// attest that governance was bypassed. Any interface presenting a
// "Verified ✓" badge must consult FullStrength, not just Valid — otherwise
// the badge asserts more than the receipt does, which is the failure mode
// this whole design exists to prevent.
type Result struct {
	// Valid reports whether the signature verified and the schema is sound.
	Valid bool

	// FullStrength reports whether the receipt attests complete governance
	// with a healthy detector. False for degraded and bypassed receipts,
	// which are still Valid.
	FullStrength bool

	// Mode is the governance mode the receipt attests.
	Mode Mode

	// Provenance is how the issuer came to know what the receipt describes.
	// Absent evidence reads as asserted, the weakest possibility.
	Provenance Provenance

	// Vantage names where the issuer stood, or who reported to it.
	Vantage string

	// Decision is the enforcement action the receipt attests.
	Decision Decision

	// KeyID identifies the key that signed the receipt.
	KeyID string

	// Algorithm is the signature scheme used.
	Algorithm Algorithm

	// IssuedAt is the parsed issuance time.
	IssuedAt time.Time

	// Digest is the receipt's SHA-256 digest, which is what a successor
	// receipt's PrevHash must match and what an anchor commits to.
	Digest string

	// Warnings are conditions that do not invalidate the receipt but that a
	// reader should see: degraded governance, an unverified actor identity,
	// missing timestamp anchors. Present these; do not swallow them.
	Warnings []string
}

// Verify checks a receipt's signature and schema without any network access.
//
// The order is deliberate. Cheap structural checks run before the signature
// so a malformed receipt fails fast, but the signature is checked before any
// semantic interpretation is reported, so nothing derived from unverified
// content is ever handed back to a caller as fact.
func Verify(r *Receipt, keys KeyResolver, opts VerifyOptions) (*Result, error) {
	return verify(r, nil, keys, opts)
}

// VerifyJSON checks a receipt exactly as it arrived.
//
// Prefer this wherever the original bytes are available, which is almost
// everywhere: a receipt arrives as a file, a response body, or a log line.
//
// The difference matters when the schema has grown since this build. Verify
// hashes a re-serialised struct, so a field this version does not know is
// dropped before canonicalisation and the signature fails — reported as
// tampering, which is the worst possible false alarm and the one thing that
// would make an old verifier untrustworthy rather than merely old.
//
// VerifyJSON canonicalises the document as received, so unknown members stay
// in the hash and the signature still checks. The result reports them, so a
// reader knows their tool is older than the receipt and that some claim in
// it went unread.
func VerifyJSON(raw []byte, keys KeyResolver, opts VerifyOptions) (*Result, error) {
	var r Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("receipt: reading the receipt: %w", err)
	}
	return verify(&r, raw, keys, opts)
}

func verify(r *Receipt, raw []byte, keys KeyResolver, opts VerifyOptions) (*Result, error) {
	if r == nil {
		return nil, errors.New("receipt: nil receipt")
	}
	if keys == nil {
		return nil, errors.New("receipt: nil key resolver")
	}

	if r.Signature == nil {
		return nil, ErrNoSignature
	}
	sig := r.Signature

	if sig.Canonicalization != CanonicalizationJCS {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCanonicalization, sig.Canonicalization)
	}
	if !opts.algorithmAccepted(sig.Algorithm) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, sig.Algorithm)
	}

	// A receipt that disagrees with itself about which key signed it must
	// not be accepted, even if one of the two IDs resolves to a key that
	// verifies. Otherwise an attacker could present a valid signature under
	// a key of their choosing while attributing the receipt to someone else.
	if sig.KeyID != r.Issuer.KeyID {
		return nil, fmt.Errorf("%w: signature %q, issuer %q",
			ErrKeyMismatch, sig.KeyID, r.Issuer.KeyID)
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	issuedAt, err := ParseTime(r.IssuedAt)
	if err != nil {
		return nil, err
	}
	now := opts.now()
	if issuedAt.After(now.Add(opts.skew())) {
		return nil, fmt.Errorf("receipt: issued %s in the future, beyond the permitted clock skew",
			issuedAt.Sub(now).Round(time.Second))
	}
	if opts.MaxAge > 0 && now.Sub(issuedAt) > opts.MaxAge {
		return nil, fmt.Errorf("receipt: issued %s ago, exceeding the maximum accepted age of %s",
			now.Sub(issuedAt).Round(time.Second), opts.MaxAge)
	}

	// Two ways to obtain the signing key, and the difference matters.
	//
	// Without an attestation, the key ID must resolve against the keys the
	// verifier already trusts — the deployment's own published set.
	//
	// With one, the receipt supplies its own public key, and the only
	// reason to believe it is the deployment's signature over the statement
	// that carries it. That signature is checked first, against the same
	// trusted set. A verifier that took the embedded key on faith would
	// accept a receipt from anyone able to generate a keypair.
	var pub crypto.PublicKey
	if att := r.Issuer.KeyAttestation; att != nil {
		pub, err = att.Verify(keys, now)
		if err != nil {
			return nil, err
		}
		if att.KeyID != sig.KeyID {
			return nil, fmt.Errorf("%w: the attestation names key %q but the receipt is signed by %q",
				ErrKeyMismatch, att.KeyID, sig.KeyID)
		}
		if att.Algorithm != sig.Algorithm {
			return nil, fmt.Errorf("%w: the attestation names algorithm %s but the receipt declares %s",
				ErrUnsupportedAlgorithm, att.Algorithm, sig.Algorithm)
		}
		// Scope is what separates one customer from another. A valid
		// attestation proves a key is legitimate; only the scope check
		// proves it is legitimate *for this chain*. Without it any
		// customer could issue receipts against another's chain and they
		// would verify perfectly.
		if !att.CoversChain(r.Chain.ID) {
			return nil, fmt.Errorf("%w: key %q is attested for %q but the receipt is on chain %q",
				ErrAttestationScope, att.KeyID, att.Scope, r.Chain.ID)
		}
	} else {
		pub, err = keys.ResolveKey(sig.KeyID)
		if err != nil {
			return nil, err
		}
	}

	info := algorithms[sig.Algorithm]
	// Confirm the resolved key is the right type for the declared
	// algorithm before verifying. Without this check, an algorithm
	// identifier and a key type could be mismatched in ways that push the
	// decision into the verifier's error handling rather than failing
	// cleanly here.
	if !info.publicKeyOK(pub) {
		return nil, fmt.Errorf("%w: resolved key for %q is not valid for algorithm %s",
			ErrUnsupportedAlgorithm, sig.KeyID, sig.Algorithm)
	}

	signature, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not valid base64", ErrBadSignature)
	}

	// Over the bytes as received where they are available, so a receipt
	// carrying a field this build has never heard of still verifies.
	var input []byte
	var inputErr error
	if raw != nil {
		input, inputErr = SigningInputFromJSON(raw)
	} else {
		input, inputErr = SigningInput(r)
	}
	err = inputErr
	if err != nil {
		return nil, err
	}

	if !info.verify(pub, input, signature) {
		return nil, ErrBadSignature
	}

	digest, err := Digest(r)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Valid:        true,
		FullStrength: r.IsFullStrength(),
		Mode:         r.Governance.Mode,
		Decision:     r.Governance.Decision,
		KeyID:        sig.KeyID,
		Algorithm:    sig.Algorithm,
		IssuedAt:     issuedAt,
		Digest:       digest,
		Provenance:   r.EffectiveProvenance(),
		Vantage:      vantageOf(r),
	}

	res.Warnings = collectWarnings(r)

	if opts.RequireFullStrength && !res.FullStrength {
		return res, fmt.Errorf("receipt: governance mode is %s but full strength was required",
			r.Governance.Mode)
	}

	return res, nil
}

// collectWarnings gathers conditions a reader should see but that do not
// invalidate a receipt.
func collectWarnings(r *Receipt) []string {
	var w []string

	switch r.Governance.Mode {
	case ModeDegraded:
		msg := "governance ran in degraded mode"
		for _, c := range r.Governance.Detector.Components {
			if c.Health != HealthHealthy {
				msg += "; " + c.Name + " was " + string(c.Health)
			}
		}
		w = append(w, msg)
	case ModeBypassed:
		w = append(w, "governance was bypassed: this content passed unexamined")
	}

	if !r.Actor.Verified {
		w = append(w, "actor identity was asserted but not cryptographically verified")
	}

	// How the issuer knows what it recorded. A reader comparing two
	// receipts should not have to work out that one describes bytes the
	// issuer handled and the other repeats what a third system said.
	switch r.EffectiveProvenance() {
	case ProvenanceAttested:
		w = append(w, "this record is second-hand: "+r.Evidence.Vantage+
			" reported the action and the issuer recorded it, so the receipt is only as complete as that report")
	case ProvenanceAsserted:
		if r.Evidence == nil {
			w = append(w, "the receipt does not state how the issuer knew what it recorded, "+
				"so it cannot be relied on as first-hand")
		} else {
			w = append(w, "the caller described its own action: this proves the description was governed, "+
				"not that it was accurate or that other actions were recorded")
		}
	}

	if len(r.Anchors) == 0 {
		w = append(w, "no external timestamp anchor: issuance time rests on the issuer's clock alone")
	}

	if r.Governance.Decision == DecisionLogOnly && len(r.Governance.Findings) > 0 {
		w = append(w, "findings were recorded but not enforced (log_only)")
	}

	return w
}

// vantageOf reports where the issuer stood, when it stated one.
func vantageOf(r *Receipt) string {
	if r.Evidence == nil {
		return ""
	}
	return r.Evidence.Vantage
}
