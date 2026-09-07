// Package webbotauth verifies Web Bot Auth request signatures.
//
// Web Bot Auth is a bot-specific profile of RFC 9421 HTTP Message
// Signatures: an agent signs its request with an Ed25519 key, names its key
// directory in a Signature-Agent header, and tags the signature
// "web-bot-auth" so it cannot be confused with another RFC 9421 use.
//
// An IETF working group was chartered in early 2026, and Cloudflare,
// Anthropic and OpenAI moved to production in lockstep, which has made it
// the de facto way an agent proves which software it is.
//
// # Why Lyntway verifies rather than issues
//
// Agent identity belongs to Entra, Okta, Web Bot Auth and the DID
// ecosystem. Lyntway does not issue it and should not: those layers are
// contested by companies with far more distribution, and a receipt is more
// valuable for consuming their claims than for competing with them.
//
// What a verified signature buys is the difference between "an agent
// claiming to be X did this" and "X did this". Receipts record which of the
// two they carry, so a reader can weigh them accordingly rather than being
// asked to trust an asserted string.
//
// # Scope
//
// This implements the verification half of the web-bot-auth profile, not
// all of RFC 9421. Signing is not implemented because Lyntway is the origin
// in this relationship, not the agent.
package webbotauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Tag is the value the profile requires in the signature parameters.
//
// Its purpose is domain separation. RFC 9421 signatures are used for many
// things; without a required tag, a signature produced for one purpose
// could be replayed as agent authentication.
const Tag = "web-bot-auth"

// Algorithm names the only signature algorithm this package verifies.
//
// The profile permits RSA-PSS as well. Ed25519 is what the production
// deployments use, and refusing an algorithm is safer than implementing it
// carelessly — an unsupported algorithm is rejected explicitly rather than
// waved through.
const Algorithm = "ed25519"

// Errors returned by verification.
var (
	// ErrNoSignature means the request carries no Web Bot Auth signature.
	// Not a failure in itself: most requests are unsigned, and the caller
	// decides whether that is acceptable.
	ErrNoSignature = errors.New("webbotauth: request is not signed")

	// ErrMalformed means the signature headers could not be parsed.
	ErrMalformed = errors.New("webbotauth: signature headers are malformed")

	// ErrUnsupportedAlgorithm means the signature uses an algorithm this
	// package does not verify.
	ErrUnsupportedAlgorithm = errors.New("webbotauth: unsupported signature algorithm")

	// ErrWrongTag means the signature was not produced for Web Bot Auth.
	ErrWrongTag = errors.New("webbotauth: signature is not tagged web-bot-auth")

	// ErrMissingAuthority means the signature covers neither @authority nor
	// @target-uri, so it is not bound to the host it was sent to and could
	// be replayed against a different origin.
	ErrMissingAuthority = errors.New("webbotauth: signature covers neither @authority nor @target-uri")

	// ErrExpired means the signature's validity window has passed.
	ErrExpired = errors.New("webbotauth: signature has expired")

	// ErrNotYetValid means the signature is dated in the future beyond the
	// permitted skew.
	ErrNotYetValid = errors.New("webbotauth: signature is not yet valid")

	// ErrUnknownKey means the key ID could not be resolved.
	ErrUnknownKey = errors.New("webbotauth: signing key is not known to this verifier")

	// ErrBadSignature means the signature did not verify.
	ErrBadSignature = errors.New("webbotauth: signature verification failed")
)

// KeyResolver maps a Web Bot Auth key ID to an Ed25519 public key.
//
// The key ID is the base64url SHA-256 thumbprint of the agent's JWK, per
// RFC 7638, not an arbitrary label. A resolver is typically a cache of keys
// fetched from agents' published directories, or a pinned set for agents
// the operator has explicitly allowed.
type KeyResolver interface {
	ResolveKey(keyID string) (ed25519.PublicKey, error)
}

// StaticKeys resolves from an in-memory map of key ID to public key.
type StaticKeys map[string]ed25519.PublicKey

// ResolveKey implements KeyResolver.
func (s StaticKeys) ResolveKey(keyID string) (ed25519.PublicKey, error) {
	k, ok := s[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	return k, nil
}

// Result describes a verified signature.
type Result struct {
	// KeyID is the JWK thumbprint the signature was made with.
	KeyID string

	// Label is the signature's label within the header dictionary.
	Label string

	// SignatureAgent is the directory URL the agent published, when it
	// supplied one.
	SignatureAgent string

	// Covered lists the components the signature covers.
	Covered []string

	// Created and Expires bound the signature's validity.
	Created time.Time
	Expires time.Time
}

// Options tunes verification.
type Options struct {
	// MaxClockSkew tolerates signatures created slightly in the future.
	// Defaults to 60 seconds.
	MaxClockSkew time.Duration

	// MaxAge rejects signatures older than this even when they carry no
	// expiry. Defaults to one hour.
	//
	// A signature with no upper bound on age is a replay waiting to
	// happen, so an absent expires parameter does not mean unlimited
	// validity.
	MaxAge time.Duration

	// Now overrides the clock, for tests.
	Now time.Time
}

func (o *Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

func (o *Options) skew() time.Duration {
	if o.MaxClockSkew <= 0 {
		return time.Minute
	}
	return o.MaxClockSkew
}

func (o *Options) maxAge() time.Duration {
	if o.MaxAge <= 0 {
		return time.Hour
	}
	return o.MaxAge
}

// Verify checks a request's Web Bot Auth signature.
//
// Returns ErrNoSignature when the request carries none, which callers
// should treat as "unauthenticated agent" rather than as an error.
func Verify(r *http.Request, keys KeyResolver, opts Options) (*Result, error) {
	if r == nil {
		return nil, errors.New("webbotauth: nil request")
	}
	if keys == nil {
		return nil, errors.New("webbotauth: nil key resolver")
	}

	rawInput := r.Header.Get("Signature-Input")
	rawSig := r.Header.Get("Signature")
	if rawInput == "" || rawSig == "" {
		return nil, ErrNoSignature
	}

	inputs, err := parseSignatureInput(rawInput)
	if err != nil {
		return nil, err
	}
	sigs, err := parseSignatureHeader(rawSig)
	if err != nil {
		return nil, err
	}

	// A request may carry several signatures for different purposes. Only
	// the one tagged web-bot-auth is agent authentication; the others are
	// somebody else's protocol and must not be treated as identity.
	var (
		input *signatureInput
		found bool
	)
	for _, candidate := range inputs {
		if candidate.params["tag"] == Tag {
			input = candidate
			found = true
			break
		}
	}
	if !found {
		return nil, ErrWrongTag
	}

	sigBytes, ok := sigs[input.label]
	if !ok {
		return nil, fmt.Errorf("%w: no signature for label %q", ErrMalformed, input.label)
	}

	if alg, present := input.params["alg"]; present && alg != Algorithm {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	// Binding to the host is what stops a signature captured by one origin
	// being replayed against another.
	if !input.covers("@authority") && !input.covers("@target-uri") {
		return nil, ErrMissingAuthority
	}

	// If the agent named a directory, that header must be signed — an
	// unsigned Signature-Agent could be swapped for one pointing at keys an
	// attacker controls.
	agentHeader := r.Header.Get("Signature-Agent")
	if agentHeader != "" && !input.covers("signature-agent") {
		return nil, fmt.Errorf("%w: Signature-Agent is present but not covered by the signature", ErrMalformed)
	}

	now := opts.now()
	created, expires, err := validityWindow(input, now, opts)
	if err != nil {
		return nil, err
	}

	keyID := input.params["keyid"]
	if keyID == "" {
		return nil, fmt.Errorf("%w: no keyid parameter", ErrMalformed)
	}
	pub, err := keys.ResolveKey(keyID)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: resolved key for %s is not an Ed25519 public key", ErrUnknownKey, keyID)
	}

	base, err := signatureBase(r, input)
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(pub, base, sigBytes) {
		return nil, ErrBadSignature
	}

	return &Result{
		KeyID:          keyID,
		Label:          input.label,
		SignatureAgent: agentHeader,
		Covered:        input.componentNames(),
		Created:        created,
		Expires:        expires,
	}, nil
}

// validityWindow checks created and expires against the clock.
func validityWindow(input *signatureInput, now time.Time, opts Options) (created, expires time.Time, err error) {
	if raw, ok := input.params["created"]; ok {
		secs, convErr := parseUnix(raw)
		if convErr != nil {
			return created, expires, fmt.Errorf("%w: created is not a unix timestamp", ErrMalformed)
		}
		created = time.Unix(secs, 0).UTC()
		if created.After(now.Add(opts.skew())) {
			return created, expires, ErrNotYetValid
		}
		if now.Sub(created) > opts.maxAge() {
			// An old signature is a replay risk whether or not it declared
			// an expiry.
			return created, expires, fmt.Errorf("%w: created %s ago", ErrExpired, now.Sub(created).Round(time.Second))
		}
	}

	if raw, ok := input.params["expires"]; ok {
		secs, convErr := parseUnix(raw)
		if convErr != nil {
			return created, expires, fmt.Errorf("%w: expires is not a unix timestamp", ErrMalformed)
		}
		expires = time.Unix(secs, 0).UTC()
		if now.After(expires.Add(opts.skew())) {
			return created, expires, ErrExpired
		}
	}

	return created, expires, nil
}

// JWKThumbprint computes the RFC 7638 thumbprint of an Ed25519 public key,
// which is what a Web Bot Auth keyid contains.
//
// The thumbprint is over a canonical JWK with exactly the required members
// in lexicographic order — for an OKP key that is crv, kty and x, and
// nothing else. Including any other member, or a different order, produces
// a different thumbprint and the key will simply never match.
func JWKThumbprint(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("webbotauth: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(pub))
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// KeysFromJWKS builds a resolver from a published key directory.
//
// Keys are indexed by their computed thumbprint rather than by any "kid"
// the directory supplies, because the keyid in a signature is defined as
// the thumbprint. Trusting a self-declared kid would let a directory claim
// a key ID that does not correspond to its key.
func KeysFromJWKS(jwks *JWKS) (StaticKeys, error) {
	if jwks == nil {
		return nil, errors.New("webbotauth: nil JWKS")
	}
	out := make(StaticKeys, len(jwks.Keys))
	for i, k := range jwks.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			// Skip rather than fail: a directory may legitimately publish
			// keys for algorithms this verifier does not support.
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
		if err != nil {
			return nil, fmt.Errorf("webbotauth: key %d has a malformed x parameter: %w", i, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("webbotauth: key %d is %d bytes, want %d",
				i, len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		thumb, err := JWKThumbprint(pub)
		if err != nil {
			return nil, err
		}
		out[thumb] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("webbotauth: directory published no usable Ed25519 keys")
	}
	return out, nil
}

// JWKS is a published key directory.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one published key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}
